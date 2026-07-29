import { detectProviders } from "./detect-providers";
import type { DomainScanResult, PolicyStatus } from "./types";

type GoogleDnsAnswer = {
  name: string;
  type: number;
  TTL?: number;
  data: string;
};

type GoogleDnsResponse = {
  Status: number;
  AD?: boolean;
  Answer?: GoogleDnsAnswer[];
  Comment?: string;
};

const DNS_ENDPOINT = "https://dns.google/resolve";

async function queryDns(domain: string, type: "MX" | "TXT" | "A" | "AAAA", signal: AbortSignal): Promise<GoogleDnsResponse> {
  const params = new URLSearchParams({
    name: domain,
    type,
    edns_client_subnet: "0.0.0.0/0",
  });
  const response = await fetch(`${DNS_ENDPOINT}?${params}`, { signal, cache: "no-store" });

  if (!response.ok) {
    throw new Error(`Google DNS ${type} query failed with ${response.status}`);
  }

  return (await response.json()) as GoogleDnsResponse;
}

function normalizeTxtRecord(value: string) {
  return value.replace(/^"|"$/g, "").replace(/""/g, "").trim();
}

// Status 3 is NXDOMAIN: an authoritative "this name does not exist". For the
// policy records below that is the common case, not a lookup failure.
const NXDOMAIN = 3;

function isResolved(response: GoogleDnsResponse) {
  return response.Status === 0 || response.Status === NXDOMAIN;
}

function txtAnswers(response: GoogleDnsResponse) {
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

function policyStatus(response: GoogleDnsResponse, record: string | undefined): PolicyStatus {
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

export async function scanDomain(domain: string): Promise<DomainScanResult> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);

  try {
    const [mxResponse, txtResponse, dmarcResponse, mtaStsResponse, tlsRptResponse, bimiResponse, ...dkimResponses] =
      await Promise.all([
        queryDns(domain, "MX", controller.signal),
        queryDns(domain, "TXT", controller.signal),
        queryDns(`_dmarc.${domain}`, "TXT", controller.signal),
        queryDns(`_mta-sts.${domain}`, "TXT", controller.signal),
        queryDns(`_smtp._tls.${domain}`, "TXT", controller.signal),
        queryDns(`default._bimi.${domain}`, "TXT", controller.signal),
        ...DKIM_SELECTORS.map((selector) => queryDns(`${selector}._domainkey.${domain}`, "TXT", controller.signal)),
      ]);

    const mxRecords = isResolved(mxResponse) ? (mxResponse.Answer ?? []).map((answer) => answer.data) : [];
    const txtRecords = txtAnswers(txtResponse);
    const spfRecords = getSpfRecords(txtRecords);
    const dmarcRecord = txtAnswers(dmarcResponse).find((record) => record.toLowerCase().startsWith("v=dmarc1"));
    const mtaStsRecord = txtAnswers(mtaStsResponse).find((record) => record.toLowerCase().startsWith("v=stsv1"));
    const tlsRptRecord = txtAnswers(tlsRptResponse).find((record) => record.toLowerCase().startsWith("v=tlsrptv1"));
    const bimiRecord = txtAnswers(bimiResponse).find((record) => record.toLowerCase().startsWith("v=bimi1"));
    const dkimSelectors = DKIM_SELECTORS.filter((_, index) => txtAnswers(dkimResponses[index]!).some(isDkimRecord));
    const dkimErrored = dkimResponses.every((response) => !isResolved(response));
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
      dkim: {
        status: dkimErrored ? "error" : dkimSelectors.length > 0 ? "present" : "missing",
        selectors: dkimSelectors,
      },
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

export async function scanDomains(domains: string[], concurrency: number) {
  const results = new Map<string, DomainScanResult>();
  let index = 0;

  async function worker() {
    while (index < domains.length) {
      const domain = domains[index++];
      if (!domain) continue;
      results.set(domain, await scanDomain(domain));
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, domains.length) }, () => worker()));

  return results;
}
