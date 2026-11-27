import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes } from 'node:crypto'
import { ml_kem768_x25519 as xwing } from '@noble/post-quantum/hybrid.js'
import { z } from 'zod'
import { b64u } from './encoding.js'

/**
 * Hybrid post-quantum encryption (KEM + DEM):
 *
 * 1. KEM: X-Wing (draft-connolly-cfrg-xwing-kem) = ML-KEM-768 (FIPS 203) combined
 *    with X25519. The shared secret stays safe as long as EITHER primitive holds:
 *    a future quantum computer breaks X25519 but not ML-KEM, and a classical flaw
 *    in the young ML-KEM would still leave X25519. This defends today's traffic
 *    against "harvest now, decrypt later".
 * 2. KDF: HKDF-SHA-256 binds the key to this protocol version and recipient kid.
 * 3. DEM: AES-256-GCM, with the envelope header + KEM ciphertext as AAD so no
 *    field can be swapped or edited without failing authentication.
 */
export const HYBRID_ALG = 'XWING-HKDF-SHA256-A256GCM'
const VERSION = 1
const IV_BYTES = 12
const TAG_BYTES = 16
export const MAX_PLAINTEXT_BYTES = 32 * 1024
export const KEM_CIPHERTEXT_BYTES = 1120
export const PUBLIC_KEY_BYTES = 1216

export interface HybridKeyPair {
  kid: string
  publicKey: Uint8Array
  secretKey: Uint8Array
}

export interface Envelope {
  v: typeof VERSION
  alg: typeof HYBRID_ALG
  kid: string
  ek: string
  iv: string
  ct: string
  tag: string
}

/** Deliberately vague: callers must not learn which check failed (no decryption oracle). */
export class DecryptionError extends Error {
  constructor() {
    super('decryption failed')
    this.name = 'DecryptionError'
  }
}

const b64uField = z.string().regex(/^[A-Za-z0-9_-]+$/)
export const envelopeSchema = z
  .object({
    v: z.literal(VERSION),
    alg: z.literal(HYBRID_ALG),
    kid: z.string().min(8).max(64),
    ek: b64uField.max(2000),
    iv: b64uField.max(32),
    ct: b64uField.max(Math.ceil((MAX_PLAINTEXT_BYTES * 4) / 3) + 4),
    tag: b64uField.max(32),
  })
  .strict()

function keyIdFor(publicKey: Uint8Array): string {
  return createHash('sha256').update(publicKey).digest('base64url').slice(0, 22)
}

export function generateHybridKeyPair(seed?: Uint8Array): HybridKeyPair {
  const { publicKey, secretKey } = seed ? xwing.keygen(seed) : xwing.keygen()
  return { kid: keyIdFor(publicKey), publicKey, secretKey }
}

/** Restores a key pair from its 32-byte X-Wing seed (the X-Wing secret key is the seed). */
export function hybridKeyPairFromSecret(secretKey: Uint8Array): HybridKeyPair {
  if (secretKey.length !== 32) throw new Error('X-Wing secret key must be 32 bytes')
  return generateHybridKeyPair(secretKey)
}

function deriveKey(sharedSecret: Uint8Array, kid: string): Buffer {
  return Buffer.from(hkdfSync('sha256', sharedSecret, Buffer.alloc(0), `qsafe-gateway/v${VERSION}/${kid}`, 32))
}

function aadFor(e: Pick<Envelope, 'v' | 'alg' | 'kid' | 'ek'>): Buffer {
  return Buffer.from(`${e.v}.${e.alg}.${e.kid}.${e.ek}`, 'utf8')
}

export function encrypt(recipient: { kid: string; publicKey: Uint8Array }, plaintext: Uint8Array): Envelope {
  if (plaintext.length > MAX_PLAINTEXT_BYTES) throw new Error('plaintext too large')
  if (recipient.publicKey.length !== PUBLIC_KEY_BYTES) throw new Error('invalid X-Wing public key')

  const { cipherText, sharedSecret } = xwing.encapsulate(recipient.publicKey)
  const key = deriveKey(sharedSecret, recipient.kid)
  const iv = randomBytes(IV_BYTES)
  const header = { v: VERSION, alg: HYBRID_ALG, kid: recipient.kid, ek: b64u.encode(cipherText) } as const

  const cipher = createCipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_BYTES })
  cipher.setAAD(aadFor(header))
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()])
  key.fill(0)

  return { ...header, iv: b64u.encode(iv), ct: b64u.encode(ct), tag: b64u.encode(cipher.getAuthTag()) }
}

export function decrypt(recipient: HybridKeyPair, input: unknown): Uint8Array {
  const parsed = envelopeSchema.safeParse(input)
  if (!parsed.success || parsed.data.kid !== recipient.kid) throw new DecryptionError()
  const envelope = parsed.data

  let key: Buffer | undefined
  try {
    const ek = b64u.decode(envelope.ek)
    const iv = b64u.decode(envelope.iv)
    const tag = b64u.decode(envelope.tag)
    if (ek.length !== KEM_CIPHERTEXT_BYTES || iv.length !== IV_BYTES || tag.length !== TAG_BYTES) {
      throw new DecryptionError()
    }
    // X-Wing uses implicit rejection: a tampered ek yields a random secret, and GCM then fails
    const sharedSecret = xwing.decapsulate(ek, recipient.secretKey)
    key = deriveKey(sharedSecret, recipient.kid)

    const decipher = createDecipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_BYTES })
    decipher.setAAD(aadFor(envelope))
    decipher.setAuthTag(tag)
    return new Uint8Array(Buffer.concat([decipher.update(b64u.decode(envelope.ct)), decipher.final()]))
  } catch {
    throw new DecryptionError()
  } finally {
    key?.fill(0)
  }
}
