import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

type Bucket = {
  count: number;
  resetAt: number;
};

const buckets = new Map<string, Bucket>();
const limiters = new Map<string, Ratelimit>();

const hasUpstash = Boolean(process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN);

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

export async function checkRateLimit(key: string, limit: number, windowMs: number) {
  if (hasUpstash) {
    const result = await getLimiter(limit, windowMs).limit(key);
    return { allowed: result.success, remaining: result.remaining, resetAt: result.reset };
  }

  // In-memory fallback for local dev; per-instance only, does not survive serverless cold starts.
  const now = Date.now();
  const bucket = buckets.get(key);

  if (!bucket || bucket.resetAt <= now) {
    buckets.set(key, { count: 1, resetAt: now + windowMs });
    return { allowed: true, remaining: limit - 1, resetAt: now + windowMs };
  }

  if (bucket.count >= limit) {
    return { allowed: false, remaining: 0, resetAt: bucket.resetAt };
  }

  bucket.count += 1;
  return { allowed: true, remaining: limit - bucket.count, resetAt: bucket.resetAt };
}

export function getClientIp(request: Request) {
  return request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || request.headers.get("x-real-ip") || "unknown";
}
