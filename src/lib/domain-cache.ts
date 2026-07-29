import { getCache } from "@vercel/functions";
import type { DomainScanResult } from "./types";

// Vercel's Runtime Cache, not a provisioned Redis. It ships with the platform, so
// this stays free, and the workload suits it: a cache miss just means scanning the
// domain, which is what we would have done anyway. Upstash's free tier caps at
// 10,000 requests/day and throws past that — a single large scan would exhaust it.
//
// Tradeoffs accepted: the cache is per-region and LRU-evicted, so hit rates vary
// by where the function runs and entries can disappear early. Both are fine for a
// cache and neither can produce a wrong report.

// Bump when DomainScanResult's shape changes. Cached entries are JSON snapshots of
// that type, so an unversioned key would keep serving rows missing whatever columns
// the new shape added — a silently half-empty report rather than a loud failure.
// Changing this makes old entries unreachable instead of wrong.
const CACHE_VERSION = "v1";

// DNS for a company domain is stable for days; 12h keeps a scan fresh enough to
// trust while still absorbing the repeat traffic a public tool sees.
const TTL_SECONDS = 12 * 60 * 60;

// Runtime Cache has no multi-get, so reads are individual calls issued in bounded
// batches rather than 10,000 at once.
const BATCH = 100;

// The mode is part of the key, not just the value. A run without DKIM stores
// dkim.status = "not_checked"; without the mode in the key, a later DKIM run would get
// that entry back as a hit and silently report no DKIM data for a check the user
// explicitly asked for.
function key(domain: string, includeDkim: boolean) {
  return `mxscan:${CACHE_VERSION}:${includeDkim ? "dkim" : "base"}:${domain}`;
}

// A failed scan says nothing about the domain, only about that attempt. Caching it
// would pin a transient DNS blip to every future report for 12 hours.
export function isCacheable(result: DomainScanResult) {
  return !result.error;
}

// Off-platform (local dev, tests) getCache() falls back to a per-process in-memory
// cache on its own, so this normally returns a usable store everywhere. The guard is
// only for an environment where constructing one throws outright: a scan that has
// already succeeded must not fail over a cache.
function cache() {
  try {
    return getCache();
  } catch {
    return null;
  }
}

async function inBatches<T, R>(items: T[], size: number, fn: (item: T) => Promise<R>) {
  const out: R[] = [];
  for (let i = 0; i < items.length; i += size) {
    out.push(...(await Promise.all(items.slice(i, i + size).map(fn))));
  }
  return out;
}

export async function getCachedDomains(domains: string[], includeDkim = false): Promise<Map<string, DomainScanResult>> {
  const hits = new Map<string, DomainScanResult>();
  const store = cache();
  if (!store || domains.length === 0) return hits;

  try {
    const entries = await inBatches(domains, BATCH, async (domain) => {
      const value = (await store.get(key(domain, includeDkim))) as DomainScanResult | undefined;
      return [domain, value] as const;
    });

    for (const [domain, value] of entries) {
      if (value) hits.set(domain, value);
    }
  } catch (error) {
    // A miss is always safe — scan everything rather than fail the request.
    console.error("Domain cache read failed, scanning all domains:", error);
    return new Map();
  }

  return hits;
}

export async function cacheDomains(results: Map<string, DomainScanResult>, includeDkim = false) {
  const store = cache();
  if (!store || results.size === 0) return;

  const entries = [...results].filter(([, result]) => isCacheable(result));
  if (entries.length === 0) return;

  try {
    await inBatches(entries, BATCH, ([domain, result]) =>
      store.set(key(domain, includeDkim), result, { ttl: TTL_SECONDS, tags: ["domain-scan"], name: "domain-scan" }),
    );
  } catch (error) {
    // Best-effort: the report is already correct without a write.
    console.error("Domain cache write failed:", error);
  }
}
