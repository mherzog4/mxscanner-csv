import { describe, expect, it } from "vitest";
import { checkRateLimit, getClientIp } from "./rate-limit";

// Off-platform getCache() falls back to a per-process in-memory store, so these
// exercise the real read-modify-write path rather than a stub.
describe("checkRateLimit", () => {
  it("allows up to the limit, then blocks", async () => {
    const key = `test:allow:${process.hrtime.bigint()}`;

    const first = await checkRateLimit(key, 3, 60_000);
    expect(first).toMatchObject({ allowed: true, remaining: 2 });
    expect((await checkRateLimit(key, 3, 60_000)).remaining).toBe(1);
    expect((await checkRateLimit(key, 3, 60_000)).remaining).toBe(0);

    const blocked = await checkRateLimit(key, 3, 60_000);
    expect(blocked.allowed).toBe(false);
    expect(blocked.remaining).toBe(0);
  });

  it("keeps separate counters per key", async () => {
    const stamp = process.hrtime.bigint();
    await checkRateLimit(`test:a:${stamp}`, 1, 60_000);

    expect((await checkRateLimit(`test:a:${stamp}`, 1, 60_000)).allowed).toBe(false);
    expect((await checkRateLimit(`test:b:${stamp}`, 1, 60_000)).allowed).toBe(true);
  });

  it("starts a new window once the old one expires", async () => {
    const key = `test:expiry:${process.hrtime.bigint()}`;
    // 40ms, not 1ms: two sequential calls must reliably land inside the same window,
    // and under parallel test load a 1ms window can lapse between them.
    const windowMs = 40;

    expect((await checkRateLimit(key, 1, windowMs)).allowed).toBe(true);
    expect((await checkRateLimit(key, 1, windowMs)).allowed).toBe(false);

    await new Promise((resolve) => setTimeout(resolve, windowMs * 3));
    expect((await checkRateLimit(key, 1, windowMs)).allowed).toBe(true);
  });
});

describe("getClientIp", () => {
  it("takes the first hop from x-forwarded-for", () => {
    const request = new Request("https://example.com", {
      headers: { "x-forwarded-for": "203.0.113.5, 70.41.3.18, 150.172.238.178" },
    });

    expect(getClientIp(request)).toBe("203.0.113.5");
  });

  it("falls back to x-real-ip, then to a sentinel", () => {
    expect(getClientIp(new Request("https://example.com", { headers: { "x-real-ip": "198.51.100.7" } }))).toBe(
      "198.51.100.7",
    );
    expect(getClientIp(new Request("https://example.com"))).toBe("unknown");
  });
});
