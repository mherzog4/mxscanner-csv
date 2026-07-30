import { del, get, put } from "@vercel/blob";
import { buildEnrichedCsv, getUniqueDomains, parseCsv } from "./csv-enrichment";
import { SKIPPED_ERROR, scanDomains } from "./dns";
import { cacheDomains, getCachedDomains } from "./domain-cache";
import { addContact, sendReportEmail } from "./email";
import type { DomainScanResult } from "./types";

export type ScanJob = {
  id: string;
  csvPathname: string;
  email: string;
  fileName: string;
  includeDkim: boolean;
};

// Each chunk is one step, and each step gets its own function invocation with its own
// duration budget. That is the whole point of moving off the synchronous route: total
// work is no longer bounded by a single request's 300s.
//
// 800 domains at the measured ~39/sec is ~20s of scanning per step — comfortably inside
// a step's budget even if throughput degrades well below what was measured.
const CHUNK_SIZE = 800;
const STEP_CONCURRENCY = 60;
// Per-step ceiling, not per-job. A step that stalls gets cut off and its domains come
// back marked rather than hanging the run.
const STEP_BUDGET_MS = 120_000;

const BLOB = { access: "private" } as const;

// Resend caps a message at 40MB after base64, which inflates by 4/3. Leave room for the
// HTML body. This guard lived in the route before scanning moved to a workflow and was
// lost in the move — a large report failed opaquely at the very end of a job instead.
const MAX_ATTACHMENT_BYTES = 38_000_000;

function chunk<T>(items: T[], size: number) {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

async function readBlobText(pathname: string) {
  // get() hands back a stream plus metadata — `blob` is the metadata, not a body.
  // useCache: false because a chunk written moments ago must not be served stale.
  const result = await get(pathname, { ...BLOB, useCache: false });
  if (!result?.stream) throw new Error(`Blob not found: ${pathname}`);
  return new Response(result.stream).text();
}

async function parseJob(job: ScanJob) {
  "use step";

  const parsed = await parseCsv(await readBlobText(job.csvPathname));
  const domains = getUniqueDomains(parsed);
  return { domains, rowCount: parsed.rows.length };
}

// Results are written to Blob rather than returned, so workflow state holds a pathname
// instead of megabytes of scan data. Only the pointer crosses the step boundary.
async function scanChunk(job: ScanJob, domains: string[], index: number) {
  "use step";

  const cached = await getCachedDomains(domains, job.includeDkim);
  const uncached = domains.filter((domain) => !cached.has(domain));
  const scanned = await scanDomains(uncached, STEP_CONCURRENCY, STEP_BUDGET_MS, job.includeDkim);
  await cacheDomains(scanned, job.includeDkim);

  const merged = [...cached, ...scanned];
  const pathname = `jobs/${job.id}/chunk-${index}.json`;
  await put(pathname, JSON.stringify(merged), { ...BLOB, contentType: "application/json", allowOverwrite: true });

  const skipped = merged.filter(([, result]) => result.error === SKIPPED_ERROR).length;
  console.log(`Chunk ${index}: ${domains.length} domains, ${cached.size} cached, ${skipped} skipped`);

  return pathname;
}

async function finalizeJob(job: ScanJob, chunkPaths: string[]) {
  "use step";

  const entries: [string, DomainScanResult][] = [];
  for (const pathname of chunkPaths) {
    entries.push(...(JSON.parse(await readBlobText(pathname)) as [string, DomainScanResult][]));
  }

  const parsed = await parseCsv(await readBlobText(job.csvPathname));
  const enriched = await buildEnrichedCsv(parsed, new Map(entries));

  const encodedBytes = Math.ceil(Buffer.byteLength(enriched.csv, "utf8") / 3) * 4;
  const oversized = encodedBytes > MAX_ATTACHMENT_BYTES;
  if (oversized) {
    console.error(`Job ${job.id}: enriched CSV is ${encodedBytes} bytes encoded, sending summary only`);
  }

  await sendReportEmail({
    to: job.email,
    csv: enriched.csv,
    fileName: job.fileName,
    summary: enriched.summary,
    oversized,
  });
  await addContact(job.email);

  // Uploads are transient by design — the privacy claim in the README depends on not
  // keeping them. Deletion is best-effort so a storage hiccup cannot fail a job whose
  // report has already been delivered.
  try {
    await del([job.csvPathname, ...chunkPaths]);
  } catch (error) {
    console.error(`Job ${job.id}: cleanup failed, blobs will expire on their own:`, error);
  }

  return enriched.summary;
}

export async function scanWorkflow(job: ScanJob) {
  "use workflow";

  const { domains, rowCount } = await parseJob(job);

  const chunkPaths: string[] = [];
  const batches = chunk(domains, CHUNK_SIZE);

  // Sequential on purpose. The bottleneck is resolver fair-use on a shared egress
  // range, so running chunks in parallel would reach the throttle sooner rather than
  // finish faster — the same reason more functions did not help the synchronous path.
  for (let index = 0; index < batches.length; index++) {
    chunkPaths.push(await scanChunk(job, batches[index]!, index));
  }

  const summary = await finalizeJob(job, chunkPaths);
  return { rowCount, domainCount: domains.length, summary };
}
