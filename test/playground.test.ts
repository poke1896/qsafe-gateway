import { describe, expect, it } from 'vitest'
import { buildDeps, createApp } from '../src/gateway.js'
import { loadConfig } from '../src/config.js'
import { decrypt, generateHybridKeyPair } from '../src/crypto/hybrid.js'
import { encryptForServer, fromB64u } from '../web/pq.js'

describe('browser crypto interoperability', () => {
  it('an envelope sealed with WebCrypto (browser code) opens with node:crypto (server code)', async () => {
    const server = generateHybridKeyPair()
    const message = 'cross-implementation check'
    const { envelope, timings } = await encryptForServer(server, new TextEncoder().encode(message))
    expect(new TextDecoder().decode(decrypt(server, envelope))).toBe(message)
    expect(fromB64u(envelope.ek)).toHaveLength(1120)
    expect(timings.encapsulateMs).toBeGreaterThanOrEqual(0)
  })
})

async function app(env: Record<string, string> = {}) {
  return createApp(await buildDeps(loadConfig({ NODE_ENV: 'test', ...env })))
}

describe('playground', () => {
  it('serves the page with a strict, page-specific CSP and no inline script allowance', async () => {
    const res = await (await app()).request('/')
    expect(res.status).toBe(200)
    expect(res.headers.get('content-type')).toContain('text/html')
    const csp = res.headers.get('content-security-policy') ?? ''
    expect(csp).toContain("script-src 'self'")
    expect(csp).not.toContain('unsafe-inline')
    expect(csp).toContain("frame-ancestors 'none'")
    expect(await res.text()).toContain('qsafe-gateway')
  })

  it('serves cacheable assets with ETags and honours If-None-Match', async () => {
    const a = await app()
    const js = await a.request('/app.js')
    expect(js.headers.get('content-type')).toContain('javascript')
    const etag = js.headers.get('etag') ?? ''
    expect(etag).toMatch(/^".+"$/)
    expect((await a.request('/app.js', { headers: { 'if-none-match': etag } })).status).toBe(304)
    expect((await a.request('/app.css')).headers.get('content-type')).toContain('text/css')
  })

  it('keeps the API CSP locked down', async () => {
    const res = await (await app()).request('/.well-known/jwks.json')
    expect(res.headers.get('content-security-policy')).toBe("default-src 'none'; frame-ancestors 'none'")
  })

  it('publishes low-privilege sandbox credentials that cannot rotate keys', async () => {
    const a = await app()
    const cfg = (await (await a.request('/playground/config')).json()) as { clientId: string; clientSecret: string }
    const basic = `Basic ${Buffer.from(`${cfg.clientId}:${cfg.clientSecret}`).toString('base64')}`
    const form = (scope: string) =>
      a.request('/oauth/token', {
        method: 'POST',
        headers: { authorization: basic, 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'client_credentials', scope }),
      })
    expect((await form('profile:read messages:write')).status).toBe(200)
    expect((await form('keys:rotate')).status).toBe(400)
  })

  it('can be disabled, which also removes the sandbox client', async () => {
    const a = await app({ PLAYGROUND_ENABLED: 'false' })
    expect((await a.request('/playground/config')).status).toBe(404)
    expect(() => loadConfig({ NODE_ENV: 'production', DEMO_READER_SECRET: 'x'.repeat(32), DEMO_ADMIN_SECRET: 'y'.repeat(32) })).toThrow(
      'PLAYGROUND_SECRET',
    )
  })
})
