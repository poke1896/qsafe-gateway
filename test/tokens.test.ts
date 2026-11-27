import { SignJWT, UnsecuredJWT, decodeProtectedHeader } from 'jose'
import { beforeEach, describe, expect, it } from 'vitest'
import { RevocationList } from '../src/auth/revocation.js'
import { InvalidTokenError, TokenService, hasScopes } from '../src/auth/tokens.js'
import { SigningKeyStore, generateSigningJwk } from '../src/keys/signingKeys.js'

const ISSUER = 'https://issuer.test'
const AUDIENCE = 'qsafe-api'
const TTL = 300
const GRACE = 600

let clock: number
const now = () => clock

async function setup() {
  const keys = await SigningKeyStore.create({ graceSeconds: GRACE, now })
  const revocations = new RevocationList(now)
  const tokens = new TokenService({ issuer: ISSUER, audience: AUDIENCE, ttlSeconds: TTL, keys, revocations, now })
  return { keys, tokens }
}

const rejects = async (p: Promise<unknown>, reason?: string) => {
  const error = await p.then(
    () => undefined,
    (e: unknown) => e,
  )
  expect(error).toBeInstanceOf(InvalidTokenError)
  if (reason) expect((error as InvalidTokenError).reason).toBe(reason)
}

beforeEach(() => {
  clock = Date.UTC(2026, 0, 1)
})

describe('access tokens', () => {
  it('issues an RFC 9068 ES256 token with a kid that verifies', async () => {
    const { keys, tokens } = await setup()
    const { token, jti } = await tokens.issue('demo-reader', ['profile:read'])
    expect(decodeProtectedHeader(token)).toEqual({ alg: 'ES256', kid: keys.current().kid, typ: 'at+jwt' })
    const claims = await tokens.verify(token)
    expect(claims).toMatchObject({ iss: ISSUER, aud: AUDIENCE, sub: 'demo-reader', scope: 'profile:read', jti })
    expect(claims.exp - claims.iat).toBe(TTL)
    expect(hasScopes(claims, ['profile:read'])).toBe(true)
    expect(hasScopes(claims, ['keys:rotate'])).toBe(false)
  })

  it('rejects expired tokens (beyond the 5 s clock tolerance)', async () => {
    const { tokens } = await setup()
    const { token } = await tokens.issue('demo-reader', ['profile:read'])
    clock += (TTL + 6) * 1000
    await rejects(tokens.verify(token), 'ERR_JWT_EXPIRED')
  })

  it('rejects unsigned "alg: none" tokens', async () => {
    const { tokens } = await setup()
    const forged = new UnsecuredJWT({ scope: 'keys:rotate', client_id: 'x' })
      .setIssuer(ISSUER)
      .setAudience(AUDIENCE)
      .setSubject('attacker')
      .setIssuedAt()
      .setExpirationTime('5m')
      .encode()
    await rejects(tokens.verify(forged))
  })

  it('rejects HS256 algorithm-confusion tokens keyed with the public JWK', async () => {
    const { keys, tokens } = await setup()
    const publicJwkAsSecret = new TextEncoder().encode(JSON.stringify(keys.jwks().keys[0]))
    const forged = await new SignJWT({ scope: 'keys:rotate', client_id: 'x' })
      .setProtectedHeader({ alg: 'HS256', kid: keys.current().kid, typ: 'at+jwt' })
      .setIssuer(ISSUER)
      .setAudience(AUDIENCE)
      .setSubject('attacker')
      .setIssuedAt(clock / 1000)
      .setExpirationTime(clock / 1000 + 60)
      .setJti('forged')
      .sign(publicJwkAsSecret)
    await rejects(tokens.verify(forged))
  })

  it('rejects tokens signed by a key that is not in the JWKS', async () => {
    const { tokens } = await setup()
    const other = await SigningKeyStore.create({ graceSeconds: GRACE, privateJwks: [await generateSigningJwk()], now })
    const foreign = new TokenService({
      issuer: ISSUER,
      audience: AUDIENCE,
      ttlSeconds: TTL,
      keys: other,
      revocations: new RevocationList(now),
      now,
    })
    await rejects(tokens.verify((await foreign.issue('demo-admin', ['keys:rotate'])).token))
  })

  it('rejects a tampered payload (privilege escalation attempt)', async () => {
    const { tokens } = await setup()
    const { token } = await tokens.issue('demo-reader', ['profile:read'])
    const [header, payload, signature] = token.split('.') as [string, string, string]
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString())
    claims.scope = 'profile:read keys:rotate'
    const tampered = `${header}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.${signature}`
    await rejects(tokens.verify(tampered), 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED')
  })

  it('rejects wrong audience, wrong issuer and wrong typ', async () => {
    const { keys, tokens } = await setup()
    const sign = (header: Record<string, string>, iss: string, aud: string) =>
      new SignJWT({ scope: 'profile:read', client_id: 'demo-reader' })
        .setProtectedHeader({ alg: 'ES256', kid: keys.current().kid, typ: 'at+jwt', ...header })
        .setIssuer(iss)
        .setAudience(aud)
        .setSubject('demo-reader')
        .setIssuedAt(clock / 1000)
        .setNotBefore(clock / 1000)
        .setExpirationTime(clock / 1000 + 60)
        .setJti('j')
        .sign(keys.current().privateKey)
    await rejects(tokens.verify(await sign({}, ISSUER, 'other-api')), 'ERR_JWT_CLAIM_VALIDATION_FAILED')
    await rejects(tokens.verify(await sign({}, 'https://evil.test', AUDIENCE)), 'ERR_JWT_CLAIM_VALIDATION_FAILED')
    await rejects(tokens.verify(await sign({ typ: 'JWT' }, ISSUER, AUDIENCE)), 'ERR_JWT_CLAIM_VALIDATION_FAILED')
  })

  it('rejects oversized and malformed tokens', async () => {
    const { tokens } = await setup()
    await rejects(tokens.verify('a'.repeat(5000)), 'token too large')
    await rejects(tokens.verify('not.a.jwt'))
  })

  it('rejects revoked tokens until they would have expired', async () => {
    const { tokens } = await setup()
    const { token } = await tokens.issue('demo-reader', ['profile:read'])
    tokens.revoke(await tokens.verify(token))
    await rejects(tokens.verify(token), 'token revoked')
  })
})

describe('key rotation', () => {
  it('keeps tokens from the retired key valid during the grace window, then prunes the key', async () => {
    const { keys, tokens } = await setup()
    const { token } = await tokens.issue('demo-reader', ['profile:read'])
    const oldKid = keys.current().kid

    const { kid, previousKid } = await keys.rotate()
    expect(previousKid).toBe(oldKid)
    expect(keys.jwks().keys.map((k) => k.kid)).toEqual([kid, oldKid])
    await expect(tokens.verify(token)).resolves.toMatchObject({ sub: 'demo-reader' })

    const fresh = await tokens.issue('demo-reader', ['profile:read'])
    expect(decodeProtectedHeader(fresh.token).kid).toBe(kid)

    clock += (GRACE + 1) * 1000
    expect(keys.jwks().keys.map((k) => k.kid)).toEqual([kid])
  })

  it('never publishes private key material', async () => {
    const { keys } = await setup()
    await keys.rotate()
    for (const jwk of keys.jwks().keys) {
      expect(Object.keys(jwk).sort()).toEqual(['alg', 'crv', 'kid', 'kty', 'use', 'x', 'y'])
    }
  })

  it('loads persistent keys and uses the first one to sign', async () => {
    const jwks = [await generateSigningJwk(), await generateSigningJwk()]
    const keys = await SigningKeyStore.create({ graceSeconds: GRACE, privateJwks: jwks, now })
    expect(keys.jwks().keys).toHaveLength(2)
    expect(keys.jwks().keys[0]?.kid).toBe(keys.current().kid)
  })

  it('refuses public-only keys as signing keys', async () => {
    const publicOnly = await generateSigningJwk()
    delete publicOnly.d
    await expect(SigningKeyStore.create({ graceSeconds: GRACE, privateJwks: [publicOnly], now })).rejects.toThrow()
  })
})
