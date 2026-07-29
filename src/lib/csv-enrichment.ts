import { format } from "@fast-csv/format";
import { parseString } from "@fast-csv/parse";
import type { DomainScanResult, EnrichmentSummary } from "./types";

const EMAIL_COLUMNS = new Set(["email", "email_address", "work_email", "business_email", "primary_email"]);
const EMAIL_RE = /^[^\s@]+@([^\s@]+\.[^\s@]+)$/i;

export type ParsedCsv = {
  headers: string[];
  rows: Record<string, string>[];
  emailColumn: string | null;
};

export type EnrichedCsv = {
  csv: string;
  summary: EnrichmentSummary;
};

export function parseCsv(input: string): Promise<ParsedCsv> {
  return new Promise((resolve, reject) => {
    const rows: Record<string, string>[] = [];
    let headers: string[] = [];

    parseString(input, { headers: true, ignoreEmpty: true, trim: true })
      .on("headers", (parsedHeaders: string[]) => {
        headers = parsedHeaders;
      })
      .on("error", reject)
      .on("data", (row: Record<string, string>) => rows.push(row))
      .on("end", () => {
        const emailColumn = findEmailColumn(headers, rows);
        resolve({ headers, rows, emailColumn });
      });
  });
}

export function extractDomain(email: string | undefined) {
  const match = email?.trim().match(EMAIL_RE);
  return match?.[1]?.toLowerCase().replace(/\.$/, "") ?? null;
}

export function getUniqueDomains(parsed: ParsedCsv) {
  const domains = new Set<string>();

  for (const row of parsed.rows) {
    const email = getEmailValue(row, parsed.headers, parsed.emailColumn);
    const domain = extractDomain(email);
    if (domain) domains.add(domain);
  }

  return [...domains].sort();
}

export async function buildEnrichedCsv(parsed: ParsedCsv, scanResults: Map<string, DomainScanResult>): Promise<EnrichedCsv> {
  const appendedHeaders = [
    "mx_domain",
    "mx_status",
    "mx_records",
    "detected_seg_provider",
    "detected_seg_confidence",
    "detected_mailbox_provider",
    "detected_outbound_senders",
    "spf_status",
    "spf_record",
    "dmarc_status",
    "dmarc_policy",
    "dmarc_record",
    "mx_scan_notes",
    "mx_scan_error",
    "mx_primary_host",
    "mx_provider_evidence",
    "seg_evidence_record_type",
    "seg_evidence_record",
    "dnssec_ad",
    "mta_sts_status",
    "tls_rpt_status",
    "bimi_status",
    "dkim_status",
    "dkim_selectors",
  ];
  const outputRows: Record<string, string>[] = [];
  const providerCounts: Record<string, number> = {};
  const mailboxCounts: Record<string, number> = {};
  let validEmails = 0;

  for (const row of parsed.rows) {
    const email = getEmailValue(row, parsed.headers, parsed.emailColumn);
    const domain = extractDomain(email);
    const result = domain ? scanResults.get(domain) : undefined;

    if (domain) validEmails += 1;

    const seg = result?.classification.securityGateway;
    const firstSegEvidence = seg?.evidence[0];
    const providerName = seg?.providerName ?? "Unknown";
    providerCounts[providerName] = (providerCounts[providerName] ?? 0) + 1;

    // Row-level, same as providerCounts: "how many of my prospects are on Gmail"
    // is a per-person question, not a per-domain one.
    const mailboxName = result?.classification.mailboxProvider?.providerName ?? "Unknown";
    mailboxCounts[mailboxName] = (mailboxCounts[mailboxName] ?? 0) + 1;

    outputRows.push({
      ...row,
      mx_domain: domain ?? "",
      mx_status: result?.mx.status ?? "error",
      mx_records: result?.mx.records.join("; ") ?? "",
      detected_seg_provider: seg?.providerName ?? "",
      detected_seg_confidence: seg?.confidence ?? "unknown",
      detected_mailbox_provider: result?.classification.mailboxProvider?.providerName ?? "",
      detected_outbound_senders: result?.classification.outboundSenders.map((sender) => sender.providerName).join("; ") ?? "",
      spf_status: result?.spf.status ?? "",
      spf_record: result?.spf.records.join("; ") ?? "",
      dmarc_status: result?.dmarc.status ?? "",
      dmarc_policy: result?.dmarc.policy ?? "",
      dmarc_record: result?.dmarc.record ?? "",
      mx_scan_notes: result?.notes.join("; ") ?? (domain ? "" : "Invalid or missing email"),
      mx_scan_error: result?.error ?? (domain ? "" : "Invalid or missing email"),
      mx_primary_host: result?.mx.primaryHost ?? "",
      mx_provider_evidence: result ? formatProviderEvidence(result) : "",
      seg_evidence_record_type: firstSegEvidence?.recordType ?? "",
      seg_evidence_record: firstSegEvidence?.record ?? "",
      dnssec_ad: result?.dnssec ? String(result.dnssec.ad) : "",
      mta_sts_status: result?.mtaSts.status ?? "",
      tls_rpt_status: result?.tlsRpt.status ?? "",
      bimi_status: result?.bimi.status ?? "",
      dkim_status: result?.dkim.status ?? "",
      dkim_selectors: result?.dkim.selectors.join("; ") ?? "",
    });
  }

  const csv = await formatRows([...parsed.headers, ...appendedHeaders], outputRows);
  const scanned = [...scanResults.values()];

  return {
    csv,
    summary: {
      totalRows: parsed.rows.length,
      totalValidEmails: validEmails,
      totalUniqueDomains: scanResults.size,
      providerCounts,
      mailboxCounts,
      unknownDomains: scanned.filter((result) => !result.classification.securityGateway).length,
      deliverability: {
        // Domain-level, not row-level: these count unique domains scanned.
        dmarcEnforced: scanned.filter((r) => r.dmarc.policy === "quarantine" || r.dmarc.policy === "reject").length,
        spfMissing: scanned.filter((r) => r.spf.status === "missing" || r.spf.status === "multiple").length,
        dkimFound: scanned.filter((r) => r.dkim.status === "present").length,
        mtaStsFound: scanned.filter((r) => r.mtaSts.status === "present").length,
        bimiFound: scanned.filter((r) => r.bimi.status === "present").length,
      },
    },
  };
}

function formatProviderEvidence(result: DomainScanResult) {
  const detections = [
    result.classification.securityGateway,
    result.classification.mailboxProvider,
    ...result.classification.outboundSenders,
  ].filter((detection) => detection !== null);

  return detections
    .flatMap((detection) =>
      detection.evidence.map((evidence) => `${detection.providerName} ${detection.confidence} ${evidence.recordType}: ${evidence.record}`),
    )
    .join("; ");
}

function findEmailColumn(headers: string[], rows: Record<string, string>[]) {
  const direct = headers.find((header) => EMAIL_COLUMNS.has(header.toLowerCase()));
  if (direct) return direct;

  return headers.find((header) => rows.some((row) => EMAIL_RE.test(row[header] ?? ""))) ?? null;
}

function getEmailValue(row: Record<string, string>, headers: string[], emailColumn: string | null) {
  if (emailColumn) return row[emailColumn];
  for (const header of headers) {
    const value = row[header];
    if (EMAIL_RE.test(value ?? "")) return value;
  }
  return undefined;
}

// Excel/Sheets execute cells starting with these as formulas. Cell values here
// include DNS TXT records controlled by scanned third parties, so every output
// cell gets neutralized (OWASP CSV-injection guidance).
const FORMULA_TRIGGER = /^[=+\-@\t\r]/;

export function sanitizeCell(value: string) {
  return FORMULA_TRIGGER.test(value) ? `'${value}` : value;
}

function formatRows(headers: string[], rows: Record<string, string>[]) {
  return new Promise<string>((resolve, reject) => {
    let csv = "";
    const stream = format({ headers, writeHeaders: true });
    stream.on("error", reject);
    stream.on("data", (chunk: Buffer) => {
      csv += chunk.toString("utf8");
    });
    stream.on("end", () => resolve(csv));
    for (const row of rows) {
      stream.write(Object.fromEntries(Object.entries(row).map(([key, value]) => [key, sanitizeCell(value ?? "")])));
    }
    stream.end();
  });
}
