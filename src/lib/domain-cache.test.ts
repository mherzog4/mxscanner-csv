import { describe, expect, it } from "vitest";
import { cacheDomains, getCachedDomains, isCacheable } from "./domain-cache";
import type { DomainScanResult } from "./types";

const base: DomainScanResult = {
  domain: "example.com",
  mx: { status: "present", records: ["10 mx.example.com."] },
  spf: { status: "present", records: ["v=spf1 -all"] },
  dmarc: { status: "present", policy: "reject", record: "v=DMARC1; p=reject" },
  mtaSts: { status: "missing" },
  tlsRpt: { status: "missing" },
  bimi: { status: "missing" },
  dkim: { status: "missing", selectors: [] },
  classification: { inboundProvider: null, mailboxProvider: null, outboundSenders: [], securityGateway: null },
  notes: [],
};

describe("domain cache", () => {
  it("never caches a failed scan", () => {
    expect(isCacheable(base)).toBe(true);
    expect(isCacheable({ ...base, error: "Google DNS MX query failed with 500" })).toBe(false);
  });

  it("round-trips a scan result and reports misses as absent", async () => {
    const domain = "roundtrip-example.com";
    expect(await getCachedDomains([domain])).toEqual(new Map());

    await cacheDomains(new Map([[domain, { ...base, domain }]]));

    const hits = await getCachedDomains([domain, "never-cached-example.com"]);
    expect(hits.get(domain)?.dmarc.policy).toBe("reject");
    expect(hits.has("never-cached-example.com")).toBe(false);
  });

  it("does not store failed scans, so a DNS blip is not pinned for 12h", async () => {
    const domain = "failed-example.com";
    await cacheDomains(new Map([[domain, { ...base, domain, error: "query failed with 500" }]]));

    expect(await getCachedDomains([domain])).toEqual(new Map());
  });

  it("short-circuits on empty input", async () => {
    await expect(getCachedDomains([])).resolves.toEqual(new Map());
    await expect(cacheDomains(new Map())).resolves.toBeUndefined();
  });
});
