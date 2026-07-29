import { checkBotId } from "botid/server";
import { NextResponse } from "next/server";
import { buildEnrichedCsv, getUniqueDomains, parseCsv } from "@/lib/csv-enrichment";
import { scanDomains } from "@/lib/dns";
import { cacheDomains, getCachedDomains } from "@/lib/domain-cache";
import { addContact, sendReportEmail } from "@/lib/email";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";

export const runtime = "nodejs";
// 300s is the Fluid Compute default and the hard ceiling on Hobby. Pro/Enterprise
// can raise this to 800s if the domain cap ever grows past what fits here.
export const maxDuration = 300;

// Measured, not guessed: with two DoH resolvers at concurrency 60, 1,000 domains
// (14 queries each) complete in 3-5s. 10,000 domains lands well inside the 300s
// budget even allowing for dead domains that burn the full 10s abort.
const MAX_FILE_BYTES = 25_000_000;
const MAX_ROWS = 25_000;
const MAX_UNIQUE_DOMAINS = 10_000;
const SCAN_CONCURRENCY = 60;
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

    if (domains.length === 0) {
      return NextResponse.json({ error: "No valid email addresses were found in the CSV." }, { status: 400 });
    }

    if (domains.length > MAX_UNIQUE_DOMAINS) {
      return NextResponse.json({ error: `Too many unique domains. Max unique domains is ${MAX_UNIQUE_DOMAINS}.` }, { status: 400 });
    }

    // Domain-level results are shared across every upload, and a public tool sees
    // the same popular domains constantly, so the cache cuts both wall clock and
    // resolver load. Only the misses get scanned.
    const cached = await getCachedDomains(domains);
    const uncached = domains.filter((domain) => !cached.has(domain));
    const scanned = await scanDomains(uncached, SCAN_CONCURRENCY);
    await cacheDomains(scanned);

    const scanResults = new Map([...cached, ...scanned]);
    console.log(`Scan: ${domains.length} domains, ${cached.size} cached, ${scanned.size} resolved`);

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
