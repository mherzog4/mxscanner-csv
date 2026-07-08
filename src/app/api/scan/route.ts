import { NextResponse } from "next/server";
import { buildEnrichedCsv, getUniqueDomains, parseCsv } from "@/lib/csv-enrichment";
import { scanDomains } from "@/lib/dns-google";
import { sendReportEmail } from "@/lib/email";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";

export const runtime = "nodejs";
export const maxDuration = 60;

const MAX_FILE_BYTES = 1_000_000;
const MAX_ROWS = 5_000;
const MAX_UNIQUE_DOMAINS = 500;
const SCAN_CONCURRENCY = 20;

export async function POST(request: Request) {
  try {
    const rateLimit = checkRateLimit(`scan:${getClientIp(request)}`, 5, 60 * 60 * 1000);
    if (!rateLimit.allowed) {
      return NextResponse.json({ error: "Too many scans from this network. Try again later." }, { status: 429 });
    }

    const formData = await request.formData();
    const email = String(formData.get("email") ?? "").trim();
    const file = formData.get("file");

    if (!/^\S+@\S+\.\S+$/.test(email)) {
      return NextResponse.json({ error: "Enter a valid delivery email." }, { status: 400 });
    }

    if (!(file instanceof File)) {
      return NextResponse.json({ error: "Upload a CSV file." }, { status: 400 });
    }

    if (!file.name.toLowerCase().endsWith(".csv")) {
      return NextResponse.json({ error: "Only .csv files are supported." }, { status: 400 });
    }

    if (file.size > MAX_FILE_BYTES) {
      return NextResponse.json({ error: "CSV is too large. Max size is 1 MB." }, { status: 400 });
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

    const scanResults = await scanDomains(domains, SCAN_CONCURRENCY);
    const enriched = await buildEnrichedCsv(parsed, scanResults);
    const attachmentName = makeAttachmentName(file.name);
    const emailResult = await sendReportEmail({
      to: email,
      csv: enriched.csv,
      fileName: attachmentName,
      summary: enriched.summary,
    });

    return NextResponse.json({
      ok: true,
      messageId: emailResult?.id,
      summary: enriched.summary,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unexpected scan error";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

function makeAttachmentName(originalName: string) {
  const date = new Date().toISOString().slice(0, 10);
  const base = originalName.replace(/\.csv$/i, "").replace(/[^a-z0-9-_]+/gi, "-").replace(/^-|-$/g, "") || "prospects";
  return `mx-seg-enriched-${base}-${date}.csv`;
}
