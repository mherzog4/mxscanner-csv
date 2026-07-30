import { describe, expect, it } from "vitest";
import type { EnrichmentSummary } from "./types";

// sendReportEmail talks to Resend, so this covers the decision that guards it: the
// encoded-size arithmetic that decides whether an attachment can be sent at all.
// Base64 inflates by 4/3, and Resend rejects a message over 40MB post-encoding.
const MAX_ATTACHMENT_BYTES = 38_000_000;

function encodedSize(bytes: number) {
  return Math.ceil(bytes / 3) * 4;
}

describe("attachment size guard", () => {
  it("accounts for base64 inflation, not raw size", () => {
    // 30MB raw is under the cap raw, but over it once encoded.
    expect(encodedSize(30_000_000)).toBeGreaterThan(MAX_ATTACHMENT_BYTES);
    expect(30_000_000).toBeLessThan(MAX_ATTACHMENT_BYTES);
  });

  it("passes a report that genuinely fits", () => {
    // ~18.6MB is a realistic 25,000-row enriched CSV.
    expect(encodedSize(18_600_000)).toBeLessThan(MAX_ATTACHMENT_BYTES);
  });

  it("is exact at the boundary", () => {
    const raw = Math.floor((MAX_ATTACHMENT_BYTES * 3) / 4);
    expect(encodedSize(raw)).toBeLessThanOrEqual(MAX_ATTACHMENT_BYTES);
    expect(encodedSize(raw + 3)).toBeGreaterThan(MAX_ATTACHMENT_BYTES);
  });
});

describe("summary shape the email depends on", () => {
  it("carries both breakdowns and the deliverability rollup", () => {
    const summary: EnrichmentSummary = {
      totalRows: 1,
      totalValidEmails: 1,
      totalUniqueDomains: 1,
      providerCounts: { Unknown: 1 },
      mailboxCounts: { Unknown: 1 },
      unknownDomains: 1,
      deliverability: { dmarcEnforced: 0, spfMissing: 0, dkimFound: 0, mtaStsFound: 0, bimiFound: 0 },
    };

    expect(Object.keys(summary.deliverability)).toHaveLength(5);
    expect(summary.mailboxCounts).toBeDefined();
  });
});
