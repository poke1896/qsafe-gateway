import { createHash } from 'node:crypto'
import { beforeEach, describe, expect, it } from 'vitest'
import { buildDeps, createApp } from '../src/gateway.js'
import { loadConfig } from '../src/config.js'
import { b64u } from '../src/crypto/encoding.js'
import { encrypt } from '../src/crypto/hybrid.js'

const READER = 'reader-secret-for-tests-0123456789abcdef'
const ADMIN = 'admin-secret-for-tests-0123456789abcdefg'

let clock: number
const now = () => clock

async function setup(overrides: Record<string, string> = {}) {
  const config = loadConfig({
    NODE_ENV: 'test',
    ISSUER: 'https://api.test',
    DEMO_READER_SECRET: READER,
    DEMO_ADMIN_SECRET: ADMIN,
    TOKEN_RATE_LIMIT_PER_MINUTE: '5',
    ...overrides,
  })
  return createApp(await buildDeps(config, now))
}

type App = Awaited<ReturnType<typeof setup>>

const basic = (id: string, secret: string) => `Basic ${Buffer.from(`${id}:${secret}`).toString('base64')}`

function tokenRequest(app: App, auth: string | undefined, form: Record<string, string>) {
  return app.request('/oauth/token', {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      ...(auth ? { authorization: auth } : {}),
    },
    body: new URLSearchParams(form),
  })
}

async function getToken(app: App, id: string, secret: string, scope?: string): Promise<string> {
  const res = await tokenRequest(app, basic(id, secret), { grant_type: 'client_credentials', ...(scope ? { scope } : {}) })
  expect(res.status).toBe(200)
  return ((await res.json()) as { access_token: string }).access_token
}

const bearer = (token: string) => ({ authorization: `Bearer ${token}` })

beforeEach(() => {
  clock = Date.UTC(2026, 0, 1)
})

describe('configuration', () => {
  it('fails fast on unsafe configuration', () => {
    expect(() => loadConfig({ NODE_ENV: 'production' })).toThrow('DEMO_READER_SECRET')
    expect(() => loadConfig({ ACCESS_TOKEN_TTL_SECONDS: '900', KEY_GRACE_SECONDS: '300' })).toThrow('KEY_GRACE_SECONDS')
    expect(() => loadConfig({ DEMO_READER_SECRET: 'short' })).toThrow()
  })
})

describe('discovery', () => {
  it('serves RFC 8414 metadata and a cacheable JWKS without private members', async () => {
    const app = await setup()
    const meta = (await (await app.request('/.well-known/oauth-authorization-server')).json()) as Record<string, unknown>
    expect(meta['jwks_uri']).toBe('https://api.test/.well-known/jwks.json')
    const res = await app.request('/.well-known/jwks.json')
    expect(res.headers.get('cache-control')).toBe('public, max-age=300')
    const { keys } = (await res.json()) as { keys: Record<string, unknown>[] }
    expect(keys).toHaveLength(1)
    expect(keys[0]).not.toHaveProperty('d')
  })

  it('sends hardened security headers', async () => {
    const res = await (await setup()).request('/health')
    expect(res.headers.get('strict-transport-security')).toContain('max-age=63072000')
    expect(res.headers.get('content-security-policy')).toContain("default-src 'none'")
    expect(res.headers.get('x-content-type-options')).toBe('nosniff')
    expect(res.headers.get('x-request-id')).toBeTruthy()
  })
})

describe('token endpoint', () => {
  it('issues tokens with no-store caching and default scopes', async () => {
    const app = await setup()
    const res = await tokenRequest(app, basic('demo-reader', READER), { grant_type: 'client_credentials' })
    expect(res.status).toBe(200)
    expect(res.headers.get('cache-control')).toBe('no-store')
    const body = (await res.json()) as Record<string, unknown>
    expect(body).toMatchObject({ token_type: 'Bearer', expires_in: 300, scope: 'profile:read messages:write' })
  })

  it('rejects bad credentials, unknown clients and missing auth with invalid_client', async () => {
    const app = await setup()
    for (const auth of [basic('demo-reader', 'wrong'), basic('nobody', READER), undefined, 'Basic %%%']) {
      const res = await tokenRequest(app, auth, { grant_type: 'client_credentials' })
      expect(res.status).toBe(401)
      expect(await res.json()).toEqual({ error: 'invalid_client' })
    }
  })

  it('rejects scope escalation, unknown grants and non-form bodies', async () => {
    const app = await setup()
    const reader = basic('demo-reader', READER)
    expect((await tokenRequest(app, reader, { grant_type: 'client_credentials', scope: 'keys:rotate' })).status).toBe(400)
    expect((await tokenRequest(app, reader, { grant_type: 'password' })).status).toBe(400)
    const json = await app.request('/oauth/token', {
      method: 'POST',
      headers: { authorization: reader, 'content-type': 'application/json' },
      body: '{"grant_type":"client_credentials"}',
    })
    expect(json.status).toBe(400)
  })

  it('rate limits brute-force attempts per client IP', async () => {
    const app = await setup()
    const attempt = () => tokenRequest(app, basic('demo-reader', 'guess'), { grant_type: 'client_credentials' })
    for (let i = 0; i < 5; i++) expect((await attempt()).status).toBe(401)
    const limited = await attempt()
    expect(limited.status).toBe(429)
    expect(limited.headers.get('retry-after')).toBe('60')
    clock += 61_000
    expect((await attempt()).status).toBe(401)
  })
})

describe('protected API', () => {
  it('requires a bearer token and the right scope', async () => {
    const app = await setup()
    expect((await app.request('/api/me')).status).toBe(401)
    expect((await app.request('/api/me', { headers: bearer('garbage') })).status).toBe(401)

    const limited = await getToken(app, 'demo-reader', READER, 'messages:write')
    const forbidden = await app.request('/api/me', { headers: bearer(limited) })
    expect(forbidden.status).toBe(403)
    expect(forbidden.headers.get('www-authenticate')).toContain('insufficient_scope')

    const token = await getToken(app, 'demo-reader', READER)
    const ok = await app.request('/api/me', { headers: bearer(token) })
    expect(ok.status).toBe(200)
    expect(await ok.json()).toMatchObject({ sub: 'demo-reader', scopes: ['profile:read', 'messages:write'] })
  })

  it('accepts post-quantum encrypted messages and returns only a digest', async () => {
    const app = await setup()
    const token = await getToken(app, 'demo-reader', READER)
    const pk = (await (await app.request('/pq/public-key')).json()) as { kid: string; publicKey: string }
    const message = 'confidential payload'
    const envelope = encrypt({ kid: pk.kid, publicKey: b64u.decode(pk.publicKey) }, new TextEncoder().encode(message))

    const res = await app.request('/api/messages', {
      method: 'POST',
      headers: { ...bearer(token), 'content-type': 'application/json' },
      body: JSON.stringify(envelope),
    })
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body).toEqual({
      received: true,
      bytes: message.length,
      sha256: createHash('sha256').update(message).digest('hex'),
    })
    expect(JSON.stringify(body)).not.toContain(message)

    const tampered = await app.request('/api/messages', {
      method: 'POST',
      headers: { ...bearer(token), 'content-type': 'application/json' },
      body: JSON.stringify({ ...envelope, ct: envelope.ct.slice(0, -2) + (envelope.ct.endsWith('A') ? 'BA' : 'AA') }),
    })
    expect(tampered.status).toBe(400)
    expect(await tampered.json()).toEqual({ error: 'decryption_failed' })

    const notJson = await app.request('/api/messages', { method: 'POST', headers: bearer(token), body: '{' })
    expect(notJson.status).toBe(400)
  })

  it('rejects oversized request bodies', async () => {
    const app = await setup()
    const token = await getToken(app, 'demo-reader', READER)
    const res = await app.request('/api/messages', {
      method: 'POST',
      headers: { ...bearer(token), 'content-type': 'application/json' },
      body: JSON.stringify({ ct: 'A'.repeat(70 * 1024) }),
    })
    expect(res.status).toBe(413)
  })

  it('lets only admins rotate keys; old tokens survive the rotation', async () => {
    const app = await setup()
    const readerToken = await getToken(app, 'demo-reader', READER)
    expect((await app.request('/admin/keys/rotate', { method: 'POST', headers: bearer(readerToken) })).status).toBe(403)

    const adminToken = await getToken(app, 'demo-admin', ADMIN)
    const res = await app.request('/admin/keys/rotate', { method: 'POST', headers: bearer(adminToken) })
    expect(res.status).toBe(200)
    const { kid, previousKid } = (await res.json()) as { kid: string; previousKid: string }
    expect(kid).not.toBe(previousKid)

    const jwks = (await (await app.request('/.well-known/jwks.json')).json()) as { keys: { kid: string }[] }
    expect(jwks.keys.map((k) => k.kid)).toEqual([kid, previousKid])
    expect((await app.request('/api/me', { headers: bearer(readerToken) })).status).toBe(200)
  })

  it('revokes a token only for the client that owns it', async () => {
    const app = await setup()
    const token = await getToken(app, 'demo-reader', READER)
    const revoke = (auth: string) =>
      app.request('/oauth/revoke', {
        method: 'POST',
        headers: { authorization: auth, 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token }),
      })

    expect((await revoke(basic('demo-reader', 'wrong'))).status).toBe(401)
    expect((await revoke(basic('demo-admin', ADMIN))).status).toBe(200)
    expect((await app.request('/api/me', { headers: bearer(token) })).status).toBe(200)

    expect((await revoke(basic('demo-reader', READER))).status).toBe(200)
    expect((await app.request('/api/me', { headers: bearer(token) })).status).toBe(401)
  })

  it('returns JSON 404s and generic 500s', async () => {
    const app = await setup()
    const res = await app.request('/nope')
    expect(res.status).toBe(404)
    expect(await res.json()).toEqual({ error: 'not_found' })
  })
})

describe('persistent keys', () => {
  it('loads signing and hybrid keys from the environment', async () => {
    const { generateSigningJwk } = await import('../src/keys/signingKeys.js')
    const { generateHybridKeyPair } = await import('../src/crypto/hybrid.js')
    const hybrid = generateHybridKeyPair()
    const app = await setup({
      SIGNING_KEYS_JWKS: JSON.stringify([await generateSigningJwk()]),
      HYBRID_SECRET_KEY: b64u.encode(hybrid.secretKey),
    })
    const pk = (await (await app.request('/pq/public-key')).json()) as { kid: string }
    expect(pk.kid).toBe(hybrid.kid)
  })
})
