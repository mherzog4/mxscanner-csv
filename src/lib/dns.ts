import { detectProviders } from "./detect-providers";
import type { DomainScanResult, PolicyStatus } from "./types";

type DnsAnswer = {
  name: string;
  type: number;
  TTL?: number;
  data: string;
};

type DnsResponse = {
  Status: number;
  AD?: boolean;
  Answer?: DnsAnswer[];
  Comment?: string;
};

type DnsResolver = {
  id: string;
  url: string;
  headers: Record<string, string>;
};

// Two DoH resolvers, not one. Each domain is pinned to a resolver by position,
// which halves the query volume any single provider sees — the fair-use headroom
// is what caps how many domains a scan can cover.
//
// Both speak the same RFC 8484 JSON shape (verified: identical Status/Answer
// fields for the same query), so nothing downstream cares which answered.
//
// Node's own resolver is deliberately not used here: in serverless it goes
// through the platform resolver, which rate-limits hard (~1k packets/sec per
// interface) and returns EREFUSED under the concurrency this scan needs. DoH
// measured an order of magnitude faster and did not throttle.
const RESOLVERS: DnsResolver[] = [
  { id: "google", url: "https://dns.google/resolve", headers: {} },
  { id: "cloudflare", url: "https://cloudflare-dns.com/dns-query", headers: { accept: "application/dns-json" } },
];

type RecordType = "MX" | "TXT" | "A" | "AAAA";

async function queryOne(resolver: DnsResolver, name: string, type: RecordType, signal: AbortSignal): Promise<DnsResponse> {
  const params = new URLSearchParams({ name, type, edns_client_subnet: "0.0.0.0/0" });
  const response = await fetch(`${resolver.url}?${params}`, {
    headers: resolver.headers,
    signal,
    cache: "no-store",
  });

  if (!response.ok) {
    throw new Error(`${resolver.id} DNS ${type} query for ${name} failed with ${response.status}`);
  }

  return (await response.json()) as DnsResponse;
}

// Try the pinned resolver, then the other one. A provider hiccup or a throttle
// response costs one retry instead of failing the whole domain.
async function queryDns(startIndex: number, name: string, type: RecordType, signal: AbortSignal): Promise<DnsResponse> {
  let lastError: unknown;

  for (let attempt = 0; attempt < RESOLVERS.length; attempt++) {
    // The shared 10s budget is already blown; retrying elsewhere cannot help.
    if (signal.aborted) break;

    try {
      return await queryOne(RESOLVERS[(startIndex + attempt) % RESOLVERS.length]!, name, type, signal);
    } catch (error) {
      lastError = error;
    }
  }

  throw lastError instanceof Error ? lastError : new Error(`DNS ${type} query for ${name} failed`);
}

function normalizeTxtRecord(value: string) {
  return value.replace(/^"|"$/g, "").replace(/""/g, "").trim();
}

// Status 3 is NXDOMAIN: an authoritative "this name does not exist". For the
// policy records below that is the common case, not a lookup failure.
const NXDOMAIN = 3;

function isResolved(response: DnsResponse) {
  return response.Status === 0 || response.Status === NXDOMAIN;
}

function txtAnswers(response: DnsResponse) {
  return isResolved(response) ? (response.Answer ?? []).map((answer) => normalizeTxtRecord(answer.data)) : [];
}

function getSpfRecords(txtRecords: string[]) {
  return txtRecords.filter((record) => record.toLowerCase().startsWith("v=spf1"));
}

function getDmarcPolicy(record: string | undefined) {
  if (!record) return undefined;
  const match = record.match(/(?:^|;)\s*p\s*=\s*(none|quarantine|reject)\b/i);
  return match?.[1]?.toLowerCase() as "none" | "quarantine" | "reject" | undefined;
}

// MX answers look like "10 mxa-001.pphosted.com." — lowest preference wins.
export function getPrimaryMxHost(records: string[]) {
  const parsed = records
    .map((record) => {
      const match = record.trim().match(/^(\d+)\s+(\S+?)\.?$/);
      return match ? { priority: Number(match[1]), host: match[2]!.toLowerCase() } : null;
    })
    .filter((entry) => entry !== null);

  return parsed.sort((a, b) => a.priority - b.priority)[0]?.host;
}

function policyStatus(response: DnsResponse, record: string | undefined): PolicyStatus {
  if (!isResolved(response)) return "error";
  return record ? "present" : "missing";
}

// ponytail: fixed selector list, not a full enumeration. DKIM selectors are not
// discoverable from DNS — you can only guess names — so this covers the common
// mailbox/ESP defaults. Add entries here as new ones show up in the wild.
const DKIM_SELECTORS = ["google", "selector1", "selector2", "k1", "s1", "s2", "dkim", "mail"];

function isDkimRecord(record: string) {
  const value = record.toLowerCase();
  return value.startsWith("v=dkim1") || (value.includes("p=") && value.includes("k="));
}

// Queries issued per domain, by mode. DKIM probing is 8 of the 14 — 57% of all DNS
// traffic for the weakest signal in the report, since a miss only ever means "not on
// a selector we guessed". Turning it off is the cheapest way to raise how many domains
// a single run can cover, so it is opt-in rather than always-on.
export const QUERIES_PER_DOMAIN_BASE = 6;
export const QUERIES_PER_DOMAIN_WITH_DKIM = QUERIES_PER_DOMAIN_BASE + 8;

export type ScanOptions = { resolverIndex?: number; includeDkim?: boolean };

export async function scanDomain(domain: string, options: ScanOptions = {}): Promise<DomainScanResult> {
  const { resolverIndex = 0, includeDkim = false } = options;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);
  const q = (name: string, type: RecordType) => queryDns(resolverIndex, name, type, controller.signal);
  const selectors = includeDkim ? DKIM_SELECTORS : [];

  try {
    const [mxResponse, txtResponse, dmarcResponse, mtaStsResponse, tlsRptResponse, bimiResponse, ...dkimResponses] =
      await Promise.all([
        q(domain, "MX"),
        q(domain, "TXT"),
        q(`_dmarc.${domain}`, "TXT"),
        q(`_mta-sts.${domain}`, "TXT"),
        q(`_smtp._tls.${domain}`, "TXT"),
        q(`default._bimi.${domain}`, "TXT"),
        ...selectors.map((selector) => q(`${selector}._domainkey.${domain}`, "TXT")),
      ]);

    const mxRecords = isResolved(mxResponse) ? (mxResponse.Answer ?? []).map((answer) => answer.data) : [];
    const txtRecords = txtAnswers(txtResponse);
    const spfRecords = getSpfRecords(txtRecords);
    const dmarcRecord = txtAnswers(dmarcResponse).find((record) => record.toLowerCase().startsWith("v=dmarc1"));
    const mtaStsRecord = txtAnswers(mtaStsResponse).find((record) => record.toLowerCase().startsWith("v=stsv1"));
    const tlsRptRecord = txtAnswers(tlsRptResponse).find((record) => record.toLowerCase().startsWith("v=tlsrptv1"));
    const bimiRecord = txtAnswers(bimiResponse).find((record) => record.toLowerCase().startsWith("v=bimi1"));
    const dkimSelectors = selectors.filter((_, index) => txtAnswers(dkimResponses[index]!).some(isDkimRecord));
    // "not_checked" is distinct from "missing": one means we looked and found nothing,
    // the other means we never asked. Conflating them would misreport the whole column.
    const dkimStatus: PolicyStatus | "not_checked" = !includeDkim
      ? "not_checked"
      : dkimResponses.every((response) => !isResolved(response))
        ? "error"
        : dkimSelectors.length > 0
          ? "present"
          : "missing";
    const classification = detectProviders(mxRecords, txtRecords);
    const notes: string[] = [];

    if (classification.securityGateway) {
      notes.push(`${classification.securityGateway.providerName} detected from DNS evidence`);
    } else if (classification.mailboxProvider) {
      notes.push(`No SEG detected; ${classification.mailboxProvider.providerName} mailbox provider detected`);
    } else {
      notes.push("No known SEG or mailbox provider detected");
    }

    if (mtaStsRecord) notes.push("MTA-STS policy published");
    if (tlsRptRecord) notes.push("TLS-RPT reporting enabled");
    if (bimiRecord) notes.push("BIMI record published");
    if (dkimSelectors.length > 0) notes.push(`DKIM selectors found: ${dkimSelectors.join(", ")}`);

    return {
      domain,
      mx: {
        status: isResolved(mxResponse) ? (mxRecords.length > 0 ? "present" : "missing") : "error",
        records: mxRecords,
        primaryHost: getPrimaryMxHost(mxRecords),
      },
      spf: {
        status: isResolved(txtResponse) ? (spfRecords.length > 1 ? "multiple" : spfRecords.length === 1 ? "present" : "missing") : "error",
        records: spfRecords,
      },
      dmarc: {
        status: policyStatus(dmarcResponse, dmarcRecord),
        policy: getDmarcPolicy(dmarcRecord),
        record: dmarcRecord,
      },
      mtaSts: {
        status: policyStatus(mtaStsResponse, mtaStsRecord),
        id: mtaStsRecord?.match(/(?:^|;)\s*id\s*=\s*([^;\s]+)/i)?.[1],
      },
      tlsRpt: { status: policyStatus(tlsRptResponse, tlsRptRecord), record: tlsRptRecord },
      bimi: { status: policyStatus(bimiResponse, bimiRecord), record: bimiRecord },
      dkim: { status: dkimStatus, selectors: dkimSelectors },
      classification,
      dnssec: { ad: Boolean(mxResponse.AD || txtResponse.AD || dmarcResponse.AD) },
      notes,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown DNS scan error";
    return {
      domain,
      mx: { status: "error", records: [] },
      spf: { status: "error", records: [] },
      dmarc: { status: "error" },
      mtaSts: { status: "error" },
      tlsRpt: { status: "error" },
      bimi: { status: "error" },
      dkim: { status: "error", selectors: [] },
      classification: {
        inboundProvider: null,
        mailboxProvider: null,
        outboundSenders: [],
        securityGateway: null,
      },
      notes: [],
      error: message,
    };
  } finally {
    clearTimeout(timeout);
  }
}

export const SKIPPED_ERROR = "Scan time budget exhausted before this domain was reached";

function skippedResult(domain: string): DomainScanResult {
  return {
    domain,
    mx: { status: "error", records: [] },
    spf: { status: "error", records: [] },
    dmarc: { status: "error" },
    mtaSts: { status: "error" },
    tlsRpt: { status: "error" },
    bimi: { status: "error" },
    dkim: { status: "error", selectors: [] },
    classification: { inboundProvider: null, mailboxProvider: null, outboundSenders: [], securityGateway: null },
    notes: ["Not scanned: run exceeded its time budget"],
    error: SKIPPED_ERROR,
  };
}

// budgetMs bounds the whole batch. Without it, a run that outgrows the function's
// maxDuration is killed mid-flight and the user gets nothing — not a partial report,
// nothing, after waiting minutes. Real throughput against public DoH resolvers from
// a datacenter turned out to be far below what the same code measures from a laptop,
// so the batch has to be able to stop on its own rather than trusting a domain cap
// to have been set correctly.
//
// Domains past the deadline come back marked, so every row still gets a value and the
// report says plainly which ones were not reached.
export async function scanDomains(
  domains: string[],
  concurrency: number,
  budgetMs = Number.POSITIVE_INFINITY,
  includeDkim = false,
) {
  const results = new Map<string, DomainScanResult>();
  const deadline = Date.now() + budgetMs;
  let index = 0;

  async function worker() {
    while (index < domains.length) {
      const position = index++;
      const domain = domains[position];
      if (!domain) continue;

      results.set(
        domain,
        Date.now() >= deadline
          ? skippedResult(domain)
          : await scanDomain(domain, { resolverIndex: position % RESOLVERS.length, includeDkim }),
      );
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, domains.length) }, () => worker()));

  return results;
}
