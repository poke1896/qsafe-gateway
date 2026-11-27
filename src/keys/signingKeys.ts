import {
  calculateJwkThumbprint,
  exportJWK,
  generateKeyPair,
  importJWK,
  type CryptoKey,
  type JSONWebKeySet,
  type JWK,
} from 'jose'

/** The only algorithm this service signs or accepts (explicit allowlist). */
export const SIGNING_ALG = 'ES256'

export interface SigningKey {
  kid: string
  privateKey: CryptoKey
  publicJwk: JWK
  createdAt: number
  retiredAt?: number
}

/** Copies only the public members of a P-256 key: private material never leaves the process. */
function toPublicJwk(jwk: JWK, kid: string): JWK {
  const { kty, crv, x, y } = jwk
  if (kty !== 'EC' || crv !== 'P-256' || !x || !y) throw new Error('unsupported signing key type')
  return { kty, crv, x, y, kid, alg: SIGNING_ALG, use: 'sig' }
}

async function fromPrivateJwk(jwk: JWK, createdAt: number): Promise<SigningKey> {
  if (!jwk.d) throw new Error('signing key must be a private JWK')
  // RFC 7638 thumbprint: the key id is derived from the key itself, so it cannot be spoofed
  const kid = await calculateJwkThumbprint(jwk, 'sha256')
  const privateKey = (await importJWK({ ...jwk, alg: SIGNING_ALG }, SIGNING_ALG)) as CryptoKey
  return { kid, privateKey, publicJwk: toPublicJwk(jwk, kid), createdAt }
}

export async function generateSigningJwk(): Promise<JWK> {
  const { privateKey } = await generateKeyPair(SIGNING_ALG, { extractable: true })
  return exportJWK(privateKey)
}

/**
 * Holds the active signing key plus recently retired ones.
 *
 * Rotation never invalidates live tokens: a retired key stays published in the
 * JWKS for `graceSeconds` (>= access token TTL) so everything it signed keeps
 * validating until expiry, then it is pruned and its tokens stop verifying.
 */
export class SigningKeyStore {
  private keys: SigningKey[] = []

  private constructor(
    private readonly graceSeconds: number,
    private readonly now: () => number,
  ) {}

  static async create(options: {
    graceSeconds: number
    privateJwks?: JWK[] | undefined
    now?: () => number
  }): Promise<SigningKeyStore> {
    const store = new SigningKeyStore(options.graceSeconds, options.now ?? Date.now)
    if (options.privateJwks?.length) {
      const t = store.now()
      store.keys = await Promise.all(options.privateJwks.map((jwk) => fromPrivateJwk(jwk, t)))
      // First key signs; any others are verification-only (already retired)
      for (const key of store.keys.slice(1)) key.retiredAt = t
    } else {
      await store.rotate()
    }
    return store
  }

  current(): SigningKey {
    const key = this.keys[0]
    if (!key) throw new Error('no active signing key')
    return key
  }

  async rotate(): Promise<{ kid: string; previousKid: string | undefined }> {
    const previous = this.keys[0]
    const next = await fromPrivateJwk(await generateSigningJwk(), this.now())
    if (previous) previous.retiredAt = this.now()
    this.keys.unshift(next)
    this.prune()
    return { kid: next.kid, previousKid: previous?.kid }
  }

  /** Public JWKS (RFC 7517): active key first, then keys still inside the grace window. */
  jwks(): JSONWebKeySet {
    this.prune()
    return { keys: this.keys.map((k) => ({ ...k.publicJwk })) }
  }

  private prune(): void {
    const cutoff = this.now() - this.graceSeconds * 1000
    this.keys = this.keys.filter((k, i) => i === 0 || (k.retiredAt ?? Infinity) > cutoff)
  }
}
