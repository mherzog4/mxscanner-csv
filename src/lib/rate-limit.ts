import { getCache } from "@vercel/functions";
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

const limiters = new Map<string, Ratelimit>();

const hasUpstash = Boolean(process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN);

type Window = { count: number; resetAt: number };

function getLimiter(limit: number, windowMs: number) {
  const cacheKey = `${limit}:${windowMs}`;
  let limiter = limiters.get(cacheKey);
  if (!limiter) {
    limiter = new Ratelimit({
      redis: Redis.fromEnv(),
      limiter: Ratelimit.slidingWindow(limit, `${windowMs} ms`),
      prefix: "mxscanner",
    });
    limiters.set(cacheKey, limiter);
  }
  return limiter;
}

function cache() {
  try {
    return getCache();
  } catch {
    return null;
  }
}

// Backed by Vercel's Runtime Cache, which is shared across function instances in a
// region — unlike a process-local Map, which enforces nothing once traffic spreads
// over more than one instance.
//
// Deliberate limitation: read-modify-write is NOT atomic, so simultaneous requests
// can read the same count and both write count+1, letting a burst slip a few over.
// Counters are also per region and LRU-evictable. This throttles ordinary abuse, it
// does not survive a determined distributed attacker.
//
// The IP limit is additionally enforced at the edge by a WAF rate-limit rule, which
// blocks before the function runs and is not billed. This layer exists for the
// per-recipient-email limit, which the edge cannot see because it lives in the
// request body. Set UPSTASH_REDIS_REST_URL/_TOKEN to get true atomic counters.
async function checkRuntimeCacheLimit(key: string, limit: number, windowMs: number) {
  const store = cache();
  const now = Date.now();

  if (!store) return { allowed: true, remaining: limit - 1, resetAt: now + windowMs };

  const cacheKey = `ratelimit:${key}`;

  try {
    const current = (await store.get(cacheKey)) as Window | undefined;

    if (!current || current.resetAt <= now) {
      const fresh = { count: 1, resetAt: now + windowMs };
      // TTL in seconds, rounded up so the entry outlives the window it describes.
      await store.set(cacheKey, fresh, { ttl: Math.ceil(windowMs / 1000), tags: ["ratelimit"], name: "ratelimit" });
      return { allowed: true, remaining: limit - 1, resetAt: fresh.resetAt };
    }

    if (current.count >= limit) {
      return { allowed: false, remaining: 0, resetAt: current.resetAt };
    }

    const next = { count: current.count + 1, resetAt: current.resetAt };
    await store.set(cacheKey, next, {
      ttl: Math.max(1, Math.ceil((current.resetAt - now) / 1000)),
      tags: ["ratelimit"],
      name: "ratelimit",
    });
    return { allowed: true, remaining: limit - next.count, resetAt: next.resetAt };
  } catch (error) {
    // Fail open. A cache outage must not lock every user out of a free tool; the
    // edge rule is still enforcing the IP limit underneath this.
    console.error("Rate limit check failed, allowing request:", error);
    return { allowed: true, remaining: limit - 1, resetAt: now + windowMs };
  }
}

export async function checkRateLimit(key: string, limit: number, windowMs: number) {
  if (hasUpstash) {
    const result = await getLimiter(limit, windowMs).limit(key);
    return { allowed: result.success, remaining: result.remaining, resetAt: result.reset };
  }

  return checkRuntimeCacheLimit(key, limit, windowMs);
}

export function getClientIp(request: Request) {
  return request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || request.headers.get("x-real-ip") || "unknown";
}
