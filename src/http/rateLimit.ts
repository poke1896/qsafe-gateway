import type { MiddlewareHandler } from 'hono'

/**
 * Fixed-window, in-memory rate limiter for brute-force protection on the token
 * endpoint. Per-instance only: a multi-instance deployment would use a shared
 * store or an edge/WAF rule.
 */
export function rateLimit(options: {
  limit: number
  windowMs: number
  keyOf: (c: Parameters<MiddlewareHandler>[0]) => string
  now?: () => number
}): MiddlewareHandler {
  const now = options.now ?? Date.now
  const hits = new Map<string, { count: number; resetAt: number }>()

  return async (c, next) => {
    const t = now()
    if (hits.size > 10_000) for (const [k, v] of hits) if (v.resetAt <= t) hits.delete(k)

    const key = options.keyOf(c)
    const entry = hits.get(key)
    const window = entry && entry.resetAt > t ? entry : { count: 0, resetAt: t + options.windowMs }
    window.count += 1
    hits.set(key, window)

    const remaining = Math.max(0, options.limit - window.count)
    c.header('RateLimit-Limit', String(options.limit))
    c.header('RateLimit-Remaining', String(remaining))
    if (window.count > options.limit) {
      c.header('Retry-After', String(Math.ceil((window.resetAt - t) / 1000)))
      return c.json({ error: 'rate_limited' }, 429)
    }
    await next()
  }
}
