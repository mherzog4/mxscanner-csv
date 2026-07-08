import { detectProviders } from "./detect-providers";
import type { DomainScanResult } from "./types";

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

function getSpfRecords(txtRecords: string[]) {
  return txtRecords.filter((record) => record.toLowerCase().startsWith("v=spf1"));
}

function getDmarcPolicy(record: string | undefined) {
  if (!record) return undefined;
  const match = record.match(/(?:^|;)\s*p\s*=\s*(none|quarantine|reject)\b/i);
  return match?.[1]?.toLowerCase() as "none" | "quarantine" | "reject" | undefined;
}

export async function scanDomain(domain: string): Promise<DomainScanResult> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);

  try {
    const [mxResponse, txtResponse, dmarcResponse] = await Promise.all([
      queryDns(domain, "MX", controller.signal),
      queryDns(domain, "TXT", controller.signal),
      queryDns(`_dmarc.${domain}`, "TXT", controller.signal),
    ]);

    const mxRecords = mxResponse.Status === 0 ? (mxResponse.Answer ?? []).map((answer) => answer.data) : [];
    const txtRecords = txtResponse.Status === 0 ? (txtResponse.Answer ?? []).map((answer) => normalizeTxtRecord(answer.data)) : [];
    const dmarcRecords = dmarcResponse.Status === 0 ? (dmarcResponse.Answer ?? []).map((answer) => normalizeTxtRecord(answer.data)) : [];
    const spfRecords = getSpfRecords(txtRecords);
    const dmarcRecord = dmarcRecords.find((record) => record.toLowerCase().startsWith("v=dmarc1"));
    const classification = detectProviders(mxRecords, txtRecords);
    const notes: string[] = [];

    if (classification.securityGateway) {
      notes.push(`${classification.securityGateway.providerName} detected from DNS evidence`);
    } else if (classification.mailboxProvider) {
      notes.push(`No SEG detected; ${classification.mailboxProvider.providerName} mailbox provider detected`);
    } else {
      notes.push("No known SEG or mailbox provider detected");
    }

    return {
      domain,
      mx: {
        status: mxResponse.Status === 0 ? (mxRecords.length > 0 ? "present" : "missing") : "error",
        records: mxRecords,
      },
      spf: {
        status: txtResponse.Status === 0 ? (spfRecords.length > 1 ? "multiple" : spfRecords.length === 1 ? "present" : "missing") : "error",
        records: spfRecords,
      },
      dmarc: {
        status: dmarcResponse.Status === 0 ? (dmarcRecord ? "present" : "missing") : "error",
        policy: getDmarcPolicy(dmarcRecord),
        record: dmarcRecord,
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
