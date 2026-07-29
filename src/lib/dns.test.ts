import { afterEach, describe, expect, it } from "vitest";
import { SKIPPED_ERROR, getPrimaryMxHost, scanDomain, scanDomains } from "./dns";

describe("getPrimaryMxHost", () => {
  it("picks the lowest-preference host and strips the trailing dot", () => {
    expect(
      getPrimaryMxHost(["20 mxb-001.pphosted.com.", "10 mxa-001.pphosted.com.", "30 backup.example.net."]),
    ).toBe("mxa-001.pphosted.com");
  });

  it("sorts numerically, not lexically", () => {
    expect(getPrimaryMxHost(["100 high.example.com.", "9 low.example.com."])).toBe("low.example.com");
  });

  it("returns undefined for empty or malformed answers", () => {
    expect(getPrimaryMxHost([])).toBeUndefined();
    expect(getPrimaryMxHost(["not an mx record"])).toBeUndefined();
  });
});

describe("resolver round-robin and failover", () => {
  const realFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  function okResponse(answer: string) {
    return new Response(JSON.stringify({ Status: 0, Answer: [{ name: "x", type: 15, data: answer }] }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }

  it("spreads domains across both resolvers", async () => {
    const hosts: string[] = [];
    globalThis.fetch = (async (input: string | URL | Request) => {
      hosts.push(new URL(String(input)).host);
      return okResponse("10 mx.example.com.");
    }) as typeof fetch;

    await scanDomains(["a.com", "b.com"], 1);

    expect(new Set(hosts)).toEqual(new Set(["dns.google", "cloudflare-dns.com"]));
  });

  it("falls over to the second resolver when the first errors", async () => {
    const hosts: string[] = [];
    globalThis.fetch = (async (input: string | URL | Request) => {
      const host = new URL(String(input)).host;
      hosts.push(host);
      if (host === "dns.google") return new Response("rate limited", { status: 429 });
      return okResponse("10 mxa-001.pphosted.com.");
    }) as typeof fetch;

    // Domain at position 0 is pinned to Google, which is failing here.
    const result = await scanDomain("a.com", { resolverIndex: 0 });

    expect(hosts).toContain("cloudflare-dns.com");
    expect(result.error).toBeUndefined();
    expect(result.mx.primaryHost).toBe("mxa-001.pphosted.com");
    expect(result.classification.securityGateway?.providerName).toBe("Proofpoint");
  });

  it("reports an error when every resolver fails", async () => {
    globalThis.fetch = (async () => new Response("boom", { status: 500 })) as typeof fetch;

    const result = await scanDomain("a.com", { resolverIndex: 0 });

    expect(result.error).toBeTruthy();
    expect(result.mx.status).toBe("error");
  });
});

describe("scan time budget", () => {
  const realFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = realFetch;
  });

  it("marks domains it never reached instead of dropping them", async () => {
    let calls = 0;
    globalThis.fetch = (async () => {
      calls++;
      await new Promise((r) => setTimeout(r, 5));
      return new Response(JSON.stringify({ Status: 0, Answer: [] }), { status: 200 });
    }) as typeof fetch;

    const domains = Array.from({ length: 40 }, (_, i) => `d${i}.example.com`);
    // Budget expires almost immediately, so most domains are never attempted.
    const results = await scanDomains(domains, 2, 12);

    // Every domain still has a row — nothing is silently missing.
    expect(results.size).toBe(domains.length);

    const skipped = [...results.values()].filter((r) => r.error === SKIPPED_ERROR);
    expect(skipped.length).toBeGreaterThan(0);
    expect(skipped[0]!.notes[0]).toContain("time budget");
    // And it actually stopped issuing queries rather than running to completion.
    expect(calls).toBeLessThan(domains.length * 14);
  });

  it("scans everything when the budget is ample", async () => {
    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ Status: 0, Answer: [] }), { status: 200 })) as typeof fetch;

    const results = await scanDomains(["a.com", "b.com"], 2, 60_000);

    expect([...results.values()].every((r) => r.error !== SKIPPED_ERROR)).toBe(true);
  });
});
