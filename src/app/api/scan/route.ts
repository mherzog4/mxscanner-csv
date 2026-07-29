import { randomUUID } from "node:crypto";
import { put } from "@vercel/blob";
import { checkBotId } from "botid/server";
import { NextResponse } from "next/server";
import { start } from "workflow/api";
import { getUniqueDomains, parseCsv } from "@/lib/csv-enrichment";
import { checkRateLimit, getClientIp } from "@/lib/rate-limit";
import { scanWorkflow } from "@/lib/scan-workflow";

export const runtime = "nodejs";
// This route no longer scans. It validates, stores the upload and hands off to a
// durable workflow, so it finishes in seconds regardless of job size.
export const maxDuration = 60;

const MAX_FILE_BYTES = 25_000_000;
const MAX_ROWS = 25_000;

// Measured on a deployment, not extrapolated. A 10,000-domain job completed in 168s
// (~60 domains/sec) across 13 chunk steps, averaging 13s per step against a 120s step
// budget — roughly 9x headroom. The old synchronous path died at 5,000.
//
// Throughput per domain is *higher* at 10,000 than it was at 3,480 (60/sec vs 39/sec)
// because each chunk is a separate invocation, so the progressive resolver throttling
// that punished one long-running request no longer accumulates across the whole job.
//
// The DKIM cap is derived from the query-cost ratio (14 vs 6 per domain) rather than
// measured directly. That is safe here in a way it was not before: a chunk that runs
// long now returns its remaining domains marked, so an optimistic cap degrades into a
// partial report instead of losing the job.
const MAX_UNIQUE_DOMAINS_WITH_DKIM = 4_000;
const MAX_UNIQUE_DOMAINS = 10_000;
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

    // Hand off to a durable workflow instead of scanning inline. Each chunk becomes
    // its own step with its own duration budget, so total work is no longer bounded by
    // this request — which is what killed a 5,000-domain scan on the old path.
    const jobId = randomUUID();
    const csvPathname = `jobs/${jobId}/upload.csv`;
    await put(csvPathname, csvText, { access: "private", contentType: "text/csv" });

    const run = await start(scanWorkflow, [
      { id: jobId, csvPathname, email, fileName: makeAttachmentName(file.name), includeDkim },
    ]);

    console.log(`Job ${jobId}: queued ${domains.length} domains, dkim=${includeDkim}, run=${run.runId}`);

    return NextResponse.json(
      { ok: true, runId: run.runId, domainCount: domains.length, rowCount: parsed.rows.length },
      { status: 202 },
    );
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
