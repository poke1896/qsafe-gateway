import { randomUUID } from 'node:crypto'
import { SignJWT, createLocalJWKSet, jwtVerify, type JWTPayload } from 'jose'
import { SIGNING_ALG, type SigningKeyStore } from '../keys/signingKeys.js'
import type { RevocationList } from './revocation.js'
import type { Scope } from './clients.js'

/** RFC 9068 media type: stops an ID token or any other JWT being replayed as an access token. */
export const ACCESS_TOKEN_TYP = 'at+jwt'
const MAX_TOKEN_LENGTH = 4096
const CLOCK_TOLERANCE_SECONDS = 5

export interface AccessTokenClaims extends JWTPayload {
  sub: string
  client_id: string
  scope: string
  jti: string
  exp: number
  iat: number
}

export class InvalidTokenError extends Error {
  constructor(readonly reason: string) {
    super('invalid token')
    this.name = 'InvalidTokenError'
  }
}

export interface TokenServiceOptions {
  issuer: string
  audience: string
  ttlSeconds: number
  keys: SigningKeyStore
  revocations: RevocationList
  now?: () => number
}

export class TokenService {
  private readonly now: () => number

  constructor(private readonly options: TokenServiceOptions) {
    this.now = options.now ?? Date.now
  }

  async issue(clientId: string, scopes: Scope[]): Promise<{ token: string; expiresIn: number; jti: string }> {
    const key = this.options.keys.current()
    const iat = Math.floor(this.now() / 1000)
    const jti = randomUUID()
    const token = await new SignJWT({ client_id: clientId, scope: scopes.join(' ') })
      .setProtectedHeader({ alg: SIGNING_ALG, kid: key.kid, typ: ACCESS_TOKEN_TYP })
      .setIssuer(this.options.issuer)
      .setAudience(this.options.audience)
      .setSubject(clientId)
      .setIssuedAt(iat)
      .setNotBefore(iat)
      .setExpirationTime(iat + this.options.ttlSeconds)
      .setJti(jti)
      .sign(key.privateKey)
    return { token, expiresIn: this.options.ttlSeconds, jti }
  }

  /** Denylists the token's jti until the moment it would have expired anyway. */
  revoke(claims: AccessTokenClaims): void {
    this.options.revocations.revoke(claims.jti, claims.exp)
  }

  /**
   * Verification checks, in order: size, signature against the JWKS (by kid),
   * algorithm allowlist (blocks "none" and HS256/RS256 confusion), typ, issuer,
   * audience, exp/nbf with a small clock tolerance, required claims, revocation.
   */
  async verify(token: string): Promise<AccessTokenClaims> {
    if (token.length > MAX_TOKEN_LENGTH) throw new InvalidTokenError('token too large')
    try {
      const { payload } = await jwtVerify(token, createLocalJWKSet(this.options.keys.jwks()), {
        algorithms: [SIGNING_ALG],
        typ: ACCESS_TOKEN_TYP,
        issuer: this.options.issuer,
        audience: this.options.audience,
        clockTolerance: CLOCK_TOLERANCE_SECONDS,
        maxTokenAge: `${this.options.ttlSeconds + CLOCK_TOLERANCE_SECONDS}s`,
        requiredClaims: ['sub', 'jti', 'exp', 'iat', 'nbf', 'scope', 'client_id'],
        currentDate: new Date(this.now()),
      })
      const claims = payload as AccessTokenClaims
      if (typeof claims.scope !== 'string' || typeof claims.client_id !== 'string') {
        throw new InvalidTokenError('malformed claims')
      }
      if (this.options.revocations.isRevoked(claims.jti)) throw new InvalidTokenError('token revoked')
      return claims
    } catch (error) {
      if (error instanceof InvalidTokenError) throw error
      // jose error codes (ERR_JWT_EXPIRED, ERR_JWS_SIGNATURE_VERIFICATION_FAILED, ...) stay server-side
      const code = (error as { code?: unknown }).code
      throw new InvalidTokenError(typeof code === 'string' ? code : 'verification failed')
    }
  }
}

export function hasScopes(claims: AccessTokenClaims, required: Scope[]): boolean {
  const granted = new Set(claims.scope.split(' '))
  return required.every((s) => granted.has(s))
}
