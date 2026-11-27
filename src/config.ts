import { z } from 'zod'

// Development-only fallbacks. Production refuses to start without real secrets.
const DEV_READER_SECRET = 'dev-only-reader-secret-change-me-0001'
const DEV_ADMIN_SECRET = 'dev-only-admin-secret-change-me-00002'
const DEV_PLAYGROUND_SECRET = 'dev-only-playground-secret-change-me-03'

const schema = z
  .object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
    PORT: z.coerce.number().int().min(1).max(65535).default(8080),
    ISSUER: z.url().default('http://localhost:8080'),
    AUDIENCE: z.string().min(1).default('qsafe-api'),
    ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().min(30).max(3600).default(300),
    KEY_GRACE_SECONDS: z.coerce.number().int().min(30).max(86_400).default(600),
    TRUST_PROXY: z
      .enum(['true', 'false'])
      .default('false')
      .transform((v) => v === 'true'),
    TOKEN_RATE_LIMIT_PER_MINUTE: z.coerce.number().int().min(1).max(1000).default(20),
    DEMO_READER_SECRET: z.string().min(32).optional(),
    DEMO_ADMIN_SECRET: z.string().min(32).optional(),
    PLAYGROUND_ENABLED: z
      .enum(['true', 'false'])
      .default('true')
      .transform((v) => v === 'true'),
    PLAYGROUND_SECRET: z.string().min(32).optional(),
    SIGNING_KEYS_JWKS: z.string().min(1).optional(),
    HYBRID_SECRET_KEY: z.string().min(1).optional(),
  })
  .superRefine((env, ctx) => {
    if (env.KEY_GRACE_SECONDS < env.ACCESS_TOKEN_TTL_SECONDS) {
      ctx.addIssue({
        code: 'custom',
        path: ['KEY_GRACE_SECONDS'],
        message: 'must be >= ACCESS_TOKEN_TTL_SECONDS, otherwise key rotation breaks live tokens',
      })
    }
    if (env.NODE_ENV === 'production') {
      const required = {
        DEMO_READER_SECRET: env.DEMO_READER_SECRET,
        DEMO_ADMIN_SECRET: env.DEMO_ADMIN_SECRET,
        ...(env.PLAYGROUND_ENABLED ? { PLAYGROUND_SECRET: env.PLAYGROUND_SECRET } : {}),
      }
      for (const [key, value] of Object.entries(required)) {
        if (!value) ctx.addIssue({ code: 'custom', path: [key], message: 'required in production' })
      }
    }
  })

export interface Config {
  env: 'development' | 'test' | 'production'
  port: number
  issuer: string
  audience: string
  accessTokenTtlSeconds: number
  keyGraceSeconds: number
  trustProxy: boolean
  tokenRateLimitPerMinute: number
  readerSecret: string
  adminSecret: string
  playground: { enabled: boolean; secret: string }
  signingKeysJwks: string | undefined
  hybridSecretKey: string | undefined
}

/** Parses and validates the environment once at startup: fail fast on misconfiguration. */
export function loadConfig(source: NodeJS.ProcessEnv = process.env): Config {
  const parsed = schema.safeParse(source)
  if (!parsed.success) {
    // Report which variables are wrong, never their values
    const issues = parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')
    throw new Error(`Invalid configuration: ${issues}`)
  }
  const env = parsed.data
  return {
    env: env.NODE_ENV,
    port: env.PORT,
    issuer: env.ISSUER.replace(/\/$/, ''),
    audience: env.AUDIENCE,
    accessTokenTtlSeconds: env.ACCESS_TOKEN_TTL_SECONDS,
    keyGraceSeconds: env.KEY_GRACE_SECONDS,
    trustProxy: env.TRUST_PROXY,
    tokenRateLimitPerMinute: env.TOKEN_RATE_LIMIT_PER_MINUTE,
    readerSecret: env.DEMO_READER_SECRET ?? DEV_READER_SECRET,
    adminSecret: env.DEMO_ADMIN_SECRET ?? DEV_ADMIN_SECRET,
    playground: { enabled: env.PLAYGROUND_ENABLED, secret: env.PLAYGROUND_SECRET ?? DEV_PLAYGROUND_SECRET },
    signingKeysJwks: env.SIGNING_KEYS_JWKS,
    hybridSecretKey: env.HYBRID_SECRET_KEY,
  }
}
