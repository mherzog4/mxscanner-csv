import { describe, expect, it } from "vitest";
import { buildEnrichedCsv, getUniqueDomains, parseCsv, sanitizeCell } from "./csv-enrichment";
import type { DomainScanResult } from "./types";

const proofpointResult: DomainScanResult = {
  domain: "example.com",
  mx: { status: "present", records: ["10 mxa-001.pphosted.com"] },
  spf: { status: "present", records: ["v=spf1 include:_spf.example.com -all"] },
  dmarc: { status: "present", policy: "reject", record: "v=DMARC1; p=reject" },
  classification: {
    inboundProvider: null,
    mailboxProvider: null,
    outboundSenders: [],
    securityGateway: {
      providerId: "proofpoint",
      providerName: "Proofpoint",
      category: "seg",
      confidence: "high",
      evidence: [{ recordType: "MX", record: "10 mxa-001.pphosted.com", reason: "matched pphosted.com" }],
    },
  },
  dnssec: { ad: false },
  notes: ["Proofpoint detected from DNS evidence"],
};

describe("csv enrichment", () => {
  it("detects email columns and deduplicates normalized domains", async () => {
    const parsed = await parseCsv("Name,Email\nA,a@Example.com\nB,b@example.com\nC,c@other.com\n");

    expect(parsed.emailColumn).toBe("Email");
    expect(getUniqueDomains(parsed)).toEqual(["example.com", "other.com"]);
  });

  it("preserves rows, appends enrichment, and marks invalid emails", async () => {
    const parsed = await parseCsv("first_name,email\nJane,jane@example.com\nBad,not-an-email\n");
    const output = await buildEnrichedCsv(parsed, new Map([["example.com", proofpointResult]]));

    expect(output.summary.totalRows).toBe(2);
    expect(output.summary.totalValidEmails).toBe(1);
    expect(output.csv).toContain("first_name,email,mx_domain");
    expect(output.csv).toContain("Jane,jane@example.com,example.com,present");
    expect(output.csv).toContain("Invalid or missing email");
    expect(output.csv).toContain("mx_provider_evidence");
    expect(output.csv).toContain("Proofpoint high MX: 10 mxa-001.pphosted.com");
  });

  it("neutralizes formula-injection cells in output", async () => {
    const hostile: DomainScanResult = {
      ...proofpointResult,
      domain: "evil.com",
      spf: { status: "present", records: ['=HYPERLINK("http://evil.com","click")'] },
    };
    const parsed = await parseCsv("first_name,email\n=cmd|calc,jane@evil.com\n");
    const output = await buildEnrichedCsv(parsed, new Map([["evil.com", hostile]]));

    expect(output.csv).toContain("'=cmd|calc");
    expect(output.csv).toContain("'=HYPERLINK");
    expect(output.csv).not.toMatch(/(^|,)"?=HYPERLINK/m);
  });

  it("sanitizes only formula-trigger prefixes", () => {
    expect(sanitizeCell("=SUM(A1)")).toBe("'=SUM(A1)");
    expect(sanitizeCell("+1 555")).toBe("'+1 555");
    expect(sanitizeCell("@user")).toBe("'@user");
    expect(sanitizeCell("jane@example.com")).toBe("jane@example.com");
    expect(sanitizeCell("plain")).toBe("plain");
    expect(sanitizeCell("")).toBe("");
  });
});
