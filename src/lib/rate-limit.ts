import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";
import type { NextRequest } from "next/server";

// No Redis credentials until a database is connected (e.g. via the Vercel
// Storage tab or Upstash console) — skip limiting rather than crash routes
// that work fine without it in local dev and CI.
const redis =
  process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN
    ? new Redis({ url: process.env.UPSTASH_REDIS_REST_URL, token: process.env.UPSTASH_REDIS_REST_TOKEN })
    : null;

const limiters = new Map<string, Ratelimit>();

function getLimiter(name: string, requests: number, window: `${number} ${"s" | "m"}`) {
  if (!redis) return null;
  let limiter = limiters.get(name);
  if (!limiter) {
    limiter = new Ratelimit({
      redis,
      limiter: Ratelimit.slidingWindow(requests, window),
      prefix: `ratelimit:${name}`,
    });
    limiters.set(name, limiter);
  }
  return limiter;
}

function clientIp(req: NextRequest) {
  return req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? req.headers.get("x-real-ip") ?? "unknown";
}

/**
 * Returns null when the request is allowed, or a 429 response when the
 * per-IP limit for `name` has been exceeded. No-op (always allows) until
 * UPSTASH_REDIS_REST_URL/TOKEN are set.
 */
export async function rateLimit(
  req: NextRequest,
  name: string,
  requests: number,
  window: `${number} ${"s" | "m"}`
) {
  const limiter = getLimiter(name, requests, window);
  if (!limiter) return null;

  const { success, limit, remaining, reset } = await limiter.limit(clientIp(req));
  if (success) return null;

  return Response.json(
    { error: "Too many requests. Please slow down." },
    {
      status: 429,
      headers: {
        "X-RateLimit-Limit": String(limit),
        "X-RateLimit-Remaining": String(remaining),
        "X-RateLimit-Reset": String(reset),
      },
    }
  );
}
