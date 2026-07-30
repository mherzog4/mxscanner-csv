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

// All measured on deployments, not extrapolated:
//
//    3,480 domains    53s    66/sec    11s per chunk
//   10,000 domains   168s    60/sec    13s per chunk
//   25,000 domains   333s    75/sec    10s per chunk
//
// Scaling is linear — the rate does not degrade with size, because each chunk is a
// separate invocation so resolver throttling never accumulates across a job. Per-chunk
// time stays ~10s against a 120s step budget. The old synchronous path died at 5,000.
//
// 25,000 equals MAX_ROWS, so the domain cap is no longer a real constraint: a CSV cannot
// hold more unique domains than rows. Raising throughput further now means raising
// MAX_ROWS, and the binding limits are elsewhere (Resend's 40MB message cap, and how
// long someone will wait for an email — 5.5 minutes at this size).
//
// The DKIM cap is derived, not measured: 10,000 domains with DKIM is 140,000 queries,
// just under the 150,000 the measured 25,000-domain run issued. Safe to derive here
// because a long-running chunk returns its remaining domains marked, so an optimistic
// cap degrades into a partial report rather than losing the job.
const MAX_UNIQUE_DOMAINS_WITH_DKIM = 10_000;
const MAX_UNIQUE_DOMAINS = 25_000;
const SCAN_CONCURRENCY = 60;

// Leaves ~60s of the 300s function budget for parsing, CSV generation and the Resend
// upload. A run that outgrows this returns a report with the unreached domains marked
// rather than being killed mid-flight and delivering nothing.
const SCAN_BUDGET_MS = 240_000;

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
