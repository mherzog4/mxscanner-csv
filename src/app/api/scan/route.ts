import { checkBotId } from "botid/server";
import { NextResponse } from "next/server";
import { buildEnrichedCsv, getUniqueDomains, parseCsv } from "@/lib/csv-enrichment";
import { SKIPPED_ERROR, scanDomains } from "@/lib/dns";
import { cacheDomains, getCachedDomains } from "@/lib/domain-cache";
import { addContact, sendReportEmail } from "@/lib/email";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";

export const runtime = "nodejs";
// 300s is the Fluid Compute default and the hard ceiling on Hobby. Pro/Enterprise
// can raise this to 800s if the domain cap ever grows past what fits here.
export const maxDuration = 300;

const MAX_FILE_BYTES = 25_000_000;
const MAX_ROWS = 25_000;

// Measured in production, not extrapolated from a laptop. A local benchmark showed
// ~320 domains/sec against the DoH resolvers, but a deployed function did not finish
// 5,000 domains inside 300s — under ~17/sec effective, and 1,400 domains resolved at
// ~25/sec. Public resolvers throttle datacenter egress far harder than residential,
// and throughput degrades as sustained volume climbs, so these are not extrapolations
// from a smaller sample.
//
// The cap scales with query cost: skipping DKIM cuts 8 of 14 queries per domain, so a
// run covers proportionally more domains in the same budget.
const MAX_UNIQUE_DOMAINS_WITH_DKIM = 1_500;
const MAX_UNIQUE_DOMAINS = 3_500;
const SCAN_CONCURRENCY = 60;

// Leaves ~60s of the 300s function budget for parsing, CSV generation and the Resend
// upload. A run that outgrows this returns a report with the unreached domains marked
// rather than being killed mid-flight and delivering nothing.
const SCAN_BUDGET_MS = 240_000;
// Resend's hard limit is 40 MB post-base64; leave room for the HTML body.
const MAX_ATTACHMENT_BYTES = 38_000_000;

export async function POST(request: Request) {
  try {
    const { isBot } = await checkBotId();
    if (isBot) {
      return NextResponse.json({ error: "Automated requests are not allowed." }, { status: 403 });
    }

    const rateLimit = await checkRateLimit(`scan:${getClientIp(request)}`, 5, 60 * 60 * 1000);
    if (!rateLimit.allowed) {
      return NextResponse.json({ error: "Too many scans from this network. Try again later." }, { status: 429 });
    }

    const formData = await request.formData();
    const email = String(formData.get("email") ?? "").trim();
    const file = formData.get("file");

    if (!/^\S+@\S+\.\S+$/.test(email)) {
      return NextResponse.json({ error: "Enter a valid delivery email." }, { status: 400 });
    }

    const recipientLimit = await checkRateLimit(`report:${email.toLowerCase()}`, 3, 24 * 60 * 60 * 1000);
    if (!recipientLimit.allowed) {
      return NextResponse.json({ error: "This email already received the maximum reports for today." }, { status: 429 });
    }

    if (!(file instanceof File)) {
      return NextResponse.json({ error: "Upload a CSV file." }, { status: 400 });
    }

    if (!file.name.toLowerCase().endsWith(".csv")) {
      return NextResponse.json({ error: "Only .csv files are supported." }, { status: 400 });
    }

    if (file.size > MAX_FILE_BYTES) {
      return NextResponse.json(
        { error: `CSV is too large. Max size is ${MAX_FILE_BYTES / 1_000_000} MB.` },
        { status: 400 },
      );
    }

    const csvText = await file.text();
    const parsed = await parseCsv(csvText);

    if (parsed.rows.length === 0) {
      return NextResponse.json({ error: "CSV has no data rows." }, { status: 400 });
    }

    if (parsed.rows.length > MAX_ROWS) {
      return NextResponse.json({ error: `CSV has too many rows. Max rows is ${MAX_ROWS}.` }, { status: 400 });
    }

    const domains = getUniqueDomains(parsed);
    const includeDkim = formData.get("includeDkim") === "on";
    const domainCap = includeDkim ? MAX_UNIQUE_DOMAINS_WITH_DKIM : MAX_UNIQUE_DOMAINS;

    if (domains.length === 0) {
      return NextResponse.json({ error: "No valid email addresses were found in the CSV." }, { status: 400 });
    }

    if (domains.length > domainCap) {
      return NextResponse.json(
        {
          error: includeDkim
            ? `Too many unique domains for a DKIM scan. Max is ${domainCap.toLocaleString()} with DKIM probing, or ${MAX_UNIQUE_DOMAINS.toLocaleString()} without it.`
            : `Too many unique domains. Max unique domains is ${domainCap.toLocaleString()}.`,
        },
        { status: 400 },
      );
    }

    // Domain-level results are shared across every upload, and a public tool sees
    // the same popular domains constantly, so the cache cuts both wall clock and
    // resolver load. Only the misses get scanned.
    const cached = await getCachedDomains(domains, includeDkim);
    const uncached = domains.filter((domain) => !cached.has(domain));
    const scanned = await scanDomains(uncached, SCAN_CONCURRENCY, SCAN_BUDGET_MS, includeDkim);
    await cacheDomains(scanned, includeDkim);

    const scanResults = new Map([...cached, ...scanned]);
    const skipped = [...scanned.values()].filter((result) => result.error === SKIPPED_ERROR).length;
    console.log(
      `Scan: ${domains.length} domains, ${cached.size} cached, ${scanned.size - skipped} resolved, ${skipped} skipped, dkim=${includeDkim}`,
    );

    const enriched = await buildEnrichedCsv(parsed, scanResults);

    // Resend caps a message at 40 MB *after* base64, which inflates by 4/3. At the
    // upload limit a wide CSV plus 24 appended columns can cross that. Checked here
    // so the failure is an actionable message rather than an opaque Resend error
    // thrown away after a full scan.
    const encodedBytes = Math.ceil(Buffer.byteLength(enriched.csv, "utf8") / 3) * 4;
    if (encodedBytes > MAX_ATTACHMENT_BYTES) {
      return NextResponse.json(
        {
          error:
            "The enriched CSV is too large to email (over 40 MB encoded). Split the file into smaller batches and scan them separately.",
        },
        { status: 413 },
      );
    }

    const attachmentName = makeAttachmentName(file.name);
    const emailResult = await sendReportEmail({
      to: email,
      csv: enriched.csv,
      fileName: attachmentName,
      summary: enriched.summary,
    });

    await addContact(email);

    return NextResponse.json({
      ok: true,
      messageId: emailResult?.id,
      summary: enriched.summary,
    });
  } catch (error) {
    console.error("Scan failed:", error);
    return NextResponse.json({ error: "Unexpected scan error. Try again." }, { status: 500 });
  }
}

function makeAttachmentName(originalName: string) {
  const date = new Date().toISOString().slice(0, 10);
  const base = originalName.replace(/\.csv$/i, "").replace(/[^a-z0-9-_]+/gi, "-").replace(/^-|-$/g, "") || "prospects";
  return `mx-seg-enriched-${base}-${date}.csv`;
}
