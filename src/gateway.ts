import { createHash } from 'node:crypto'
import { Hono, type Context } from 'hono'
import { bodyLimit } from 'hono/body-limit'
import { requestId } from 'hono/request-id'
import { secureHeaders } from 'hono/secure-headers'
import type { JWK } from 'jose'
import { authenticateClient, buildClients, grantScopes, SCOPES, type Client, type Scope } from './auth/clients.js'
import { RevocationList } from './auth/revocation.js'
import { hasScopes, InvalidTokenError, TokenService, type AccessTokenClaims } from './auth/tokens.js'
import type { Config } from './config.js'
import { b64u } from './crypto/encoding.js'
import {
  decrypt,
  DecryptionError,
  generateHybridKeyPair,
  HYBRID_ALG,
  hybridKeyPairFromSecret,
  type HybridKeyPair,
} from './crypto/hybrid.js'
import { rateLimit } from './http/rateLimit.js'
import { SigningKeyStore } from './keys/signingKeys.js'
import { assets } from './web/assets.generated.js'

type Env = { Variables: { claims: AccessTokenClaims; requestId: string } }

export interface AppDeps {
  config: Config
  keys: SigningKeyStore
  tokens: TokenService
  hybridKeys: HybridKeyPair
  clients: Map<string, Client>
  now?: () => number
}

export async function buildDeps(config: Config, now: () => number = Date.now): Promise<AppDeps> {
  const privateJwks = config.signingKeysJwks ? (JSON.parse(config.signingKeysJwks) as JWK[]) : undefined
  const keys = await SigningKeyStore.create({ graceSeconds: config.keyGraceSeconds, privateJwks, now })
  const revocations = new RevocationList(now)
  const tokens = new TokenService({
    issuer: config.issuer,
    audience: config.audience,
    ttlSeconds: config.accessTokenTtlSeconds,
    keys,
    revocations,
    now,
  })
  const hybridKeys = config.hybridSecretKey
    ? hybridKeyPairFromSecret(b64u.decode(config.hybridSecretKey))
    : generateHybridKeyPair()
  const clients = buildClients({
    reader: config.readerSecret,
    admin: config.adminSecret,
    ...(config.playground.enabled ? { playground: config.playground.secret } : {}),
  })
  return { config, keys, tokens, hybridKeys, clients, now }
}

/** RFC 6749 §2.3.1: client_secret_basic, with form-urlencoded id and secret. */
function basicCredentials(header: string | undefined): { id: string; secret: string } | undefined {
  if (!header?.startsWith('Basic ')) return undefined
  try {
    const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8')
    const sep = decoded.indexOf(':')
    if (sep < 1) return undefined
    return {
      id: decodeURIComponent(decoded.slice(0, sep)),
      secret: decodeURIComponent(decoded.slice(sep + 1)),
    }
  } catch {
    return undefined
  }
}

function clientIp(c: Context, trustProxy: boolean): string {
  if (trustProxy) {
    const forwarded = c.req.header('x-forwarded-for')?.split(',')[0]?.trim()
    if (forwarded) return forwarded
  }
  const incoming = (c.env as { incoming?: { socket?: { remoteAddress?: string } } } | undefined)?.incoming
  return incoming?.socket?.remoteAddress ?? 'unknown'
}

const noStore = (c: Context) => {
  c.header('Cache-Control', 'no-store')
  c.header('Pragma', 'no-cache')
}

export function createApp(deps: AppDeps): Hono<Env> {
  const { config, keys, tokens, hybridKeys, clients } = deps
  const app = new Hono<Env>()

  app.use(requestId())
  const common = {
    strictTransportSecurity: 'max-age=63072000; includeSubDomains; preload',
    crossOriginResourcePolicy: 'same-origin',
    referrerPolicy: 'no-referrer',
  } as const
  // API responses: nothing may load or frame them
  const apiHeaders = secureHeaders({ ...common, contentSecurityPolicy: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] } })
  // Playground page: only its own script and stylesheet, no inline code, status badges from GitHub/Scorecard
  const pageHeaders = secureHeaders({
    ...common,
    contentSecurityPolicy: {
      defaultSrc: ["'none'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:', 'https://github.com', 'https://api.scorecard.dev', 'https://img.shields.io'],
      connectSrc: ["'self'"],
      baseUri: ["'none'"],
      formAction: ["'none'"],
      frameAncestors: ["'none'"],
    },
  })
  const pagePaths = new Set(['/', '/app.js', '/app.css'])
  app.use((c, next) => (pagePaths.has(c.req.path) ? pageHeaders(c, next) : apiHeaders(c, next)))
  app.use(bodyLimit({ maxSize: 64 * 1024, onError: (c) => c.json({ error: 'payload_too_large' }, 413) }))

  const requireScopes =
    (...required: Scope[]) =>
    async (c: Context<Env>, next: () => Promise<void>) => {
      const header = c.req.header('authorization')
      const token = header?.startsWith('Bearer ') ? header.slice(7).trim() : undefined
      if (!token) {
        c.header('WWW-Authenticate', 'Bearer realm="qsafe-gateway"')
        return c.json({ error: 'invalid_token' }, 401)
      }
      try {
        const claims = await tokens.verify(token)
        if (!hasScopes(claims, required)) {
          c.header('WWW-Authenticate', `Bearer error="insufficient_scope", scope="${required.join(' ')}"`)
          return c.json({ error: 'insufficient_scope' }, 403)
        }
        c.set('claims', claims)
        await next()
      } catch (error) {
        if (!(error instanceof InvalidTokenError)) throw error
        // The precise reason is logged, never returned: no oracle for attackers
        console.warn(JSON.stringify({ event: 'token_rejected', reason: error.reason, requestId: c.get('requestId') }))
        c.header('WWW-Authenticate', 'Bearer error="invalid_token"')
        return c.json({ error: 'invalid_token' }, 401)
      }
    }

  app.get('/health', (c) => c.json({ status: 'ok' }))

  // ---- Interactive playground (static assets embedded at build time) ----
  const serveAsset = (asset: { body: string; etag: string }, type: string, cache: string) => (c: Context) => {
    c.header('ETag', asset.etag)
    c.header('Cache-Control', cache)
    if (c.req.header('if-none-match') === asset.etag) return c.body(null, 304)
    c.header('Content-Type', type)
    return c.body(asset.body)
  }
  app.get('/', serveAsset(assets.html, 'text/html; charset=utf-8', 'no-cache'))
  app.get('/app.js', serveAsset(assets.js, 'text/javascript; charset=utf-8', 'public, max-age=300'))
  app.get('/app.css', serveAsset(assets.css, 'text/css; charset=utf-8', 'public, max-age=300'))
  app.get('/playground/config', (c) => {
    if (!config.playground.enabled) return c.json({ error: 'not_found' }, 404)
    noStore(c)
    // Deliberately public, low-privilege sandbox credentials (no keys:rotate)
    return c.json({ clientId: 'playground', clientSecret: config.playground.secret, scope: 'profile:read messages:write' })
  })

  // RFC 8414 authorization server metadata
  app.get('/.well-known/oauth-authorization-server', (c) =>
    c.json({
      issuer: config.issuer,
      token_endpoint: `${config.issuer}/oauth/token`,
      revocation_endpoint: `${config.issuer}/oauth/revoke`,
      jwks_uri: `${config.issuer}/.well-known/jwks.json`,
      grant_types_supported: ['client_credentials'],
      token_endpoint_auth_methods_supported: ['client_secret_basic'],
      scopes_supported: SCOPES,
      response_types_supported: ['token'],
    }),
  )

  app.get('/.well-known/jwks.json', (c) => {
    // Short cache: verifiers pick up a rotated key within minutes
    c.header('Cache-Control', 'public, max-age=300')
    return c.json(keys.jwks())
  })

  app.post(
    '/oauth/token',
    rateLimit({
      limit: config.tokenRateLimitPerMinute,
      windowMs: 60_000,
      keyOf: (c) => clientIp(c, config.trustProxy),
      ...(deps.now ? { now: deps.now } : {}),
    }),
    async (c) => {
      noStore(c)
      const credentials = basicCredentials(c.req.header('authorization'))
      const client = credentials && authenticateClient(clients, credentials.id, credentials.secret)
      if (!client) {
        c.header('WWW-Authenticate', 'Basic realm="qsafe-gateway"')
        return c.json({ error: 'invalid_client' }, 401)
      }
      if (!c.req.header('content-type')?.startsWith('application/x-www-form-urlencoded')) {
        return c.json({ error: 'invalid_request' }, 400)
      }
      const body = await c.req.parseBody()
      if (body['grant_type'] !== 'client_credentials') return c.json({ error: 'unsupported_grant_type' }, 400)
      const scopes = grantScopes(client, typeof body['scope'] === 'string' ? body['scope'] : undefined)
      if (!scopes) return c.json({ error: 'invalid_scope' }, 400)

      const { token, expiresIn } = await tokens.issue(client.id, scopes)
      return c.json({ access_token: token, token_type: 'Bearer', expires_in: expiresIn, scope: scopes.join(' ') })
    },
  )

  // RFC 7009 token revocation: a client may only revoke its own tokens; always 200
  app.post('/oauth/revoke', async (c) => {
    noStore(c)
    const credentials = basicCredentials(c.req.header('authorization'))
    const client = credentials && authenticateClient(clients, credentials.id, credentials.secret)
    if (!client) {
      c.header('WWW-Authenticate', 'Basic realm="qsafe-gateway"')
      return c.json({ error: 'invalid_client' }, 401)
    }
    const body = await c.req.parseBody()
    const token = typeof body['token'] === 'string' ? body['token'] : ''
    try {
      const claims = await tokens.verify(token)
      if (claims.client_id === client.id) tokens.revoke(claims)
    } catch {
      // Unknown, expired or foreign tokens are ignored per RFC 7009 §2.2
    }
    return c.body(null, 200)
  })

  app.get('/api/me', requireScopes('profile:read'), (c) => {
    const { sub, client_id, scope, exp, jti } = c.get('claims')
    return c.json({ sub, client_id, scopes: scope.split(' '), exp, jti })
  })

  app.get('/pq/public-key', (c) =>
    c.json({ kid: hybridKeys.kid, alg: HYBRID_ALG, publicKey: b64u.encode(hybridKeys.publicKey) }),
  )

  app.post('/api/messages', requireScopes('messages:write'), async (c) => {
    let envelope: unknown
    try {
      envelope = await c.req.json()
    } catch {
      return c.json({ error: 'invalid_request' }, 400)
    }
    try {
      const plaintext = decrypt(hybridKeys, envelope)
      // Prove receipt without echoing the secret content back
      return c.json({
        received: true,
        bytes: plaintext.length,
        sha256: createHash('sha256').update(plaintext).digest('hex'),
      })
    } catch (error) {
      if (error instanceof DecryptionError) return c.json({ error: 'decryption_failed' }, 400)
      throw error
    }
  })

  app.post('/admin/keys/rotate', requireScopes('keys:rotate'), async (c) => {
    const result = await keys.rotate()
    console.info(JSON.stringify({ event: 'signing_key_rotated', ...result, by: c.get('claims').sub }))
    return c.json(result)
  })

  app.notFound((c) => c.json({ error: 'not_found' }, 404))
  app.onError((error, c) => {
    console.error(JSON.stringify({ event: 'unhandled_error', name: error.name, requestId: c.get('requestId') }))
    return c.json({ error: 'internal_error' }, 500)
  })

  return app
}
