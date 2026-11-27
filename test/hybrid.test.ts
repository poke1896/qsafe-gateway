import { describe, expect, it } from 'vitest'
import { b64u } from '../src/crypto/encoding.js'
import {
  DecryptionError,
  KEM_CIPHERTEXT_BYTES,
  MAX_PLAINTEXT_BYTES,
  PUBLIC_KEY_BYTES,
  decrypt,
  encrypt,
  generateHybridKeyPair,
  hybridKeyPairFromSecret,
  type Envelope,
} from '../src/crypto/hybrid.js'

const text = (s: string) => new TextEncoder().encode(s)
const recipient = generateHybridKeyPair()

/** Flips one bit in a base64url field. */
function flip(value: string): string {
  const bytes = b64u.decode(value)
  bytes[0] = (bytes[0] ?? 0) ^ 0x01
  return b64u.encode(bytes)
}

describe('X-Wing hybrid encryption', () => {
  it('round-trips and uses X-Wing sizes (ML-KEM-768 + X25519)', () => {
    const envelope = encrypt(recipient, text('quantum-safe hello'))
    expect(recipient.publicKey).toHaveLength(PUBLIC_KEY_BYTES)
    expect(b64u.decode(envelope.ek)).toHaveLength(KEM_CIPHERTEXT_BYTES)
    expect(new TextDecoder().decode(decrypt(recipient, envelope))).toBe('quantum-safe hello')
  })

  it('is randomized: same plaintext gives different ciphertexts', () => {
    const a = encrypt(recipient, text('same'))
    const b = encrypt(recipient, text('same'))
    expect(a.ek).not.toBe(b.ek)
    expect(a.ct).not.toBe(b.ct)
  })

  it.each(['ek', 'iv', 'ct', 'tag'] as const)('detects tampering with %s', (field) => {
    const envelope = encrypt(recipient, text('integrity matters'))
    // eslint-disable-next-line security/detect-object-injection -- field comes from the fixed it.each list
    expect(() => decrypt(recipient, { ...envelope, [field]: flip(envelope[field]) })).toThrow(DecryptionError)
  })

  it('binds the header: a different kid or alg fails', () => {
    const envelope = encrypt(recipient, text('bound'))
    expect(() => decrypt(recipient, { ...envelope, kid: 'AAAAAAAAAAAAAAAAAAAAAA' })).toThrow(DecryptionError)
    expect(() => decrypt(recipient, { ...envelope, alg: 'A256GCM' })).toThrow(DecryptionError)
  })

  it('cannot be decrypted by another key pair, even with the kid relabelled', () => {
    const envelope = encrypt(recipient, text('only for recipient'))
    const other = generateHybridKeyPair()
    expect(() => decrypt(other, envelope)).toThrow(DecryptionError)
    expect(() => decrypt(other, { ...envelope, kid: other.kid })).toThrow(DecryptionError)
  })

  it('rejects malformed envelopes with the same generic error (no oracle)', () => {
    const envelope = encrypt(recipient, text('x'))
    const bad: unknown[] = [
      null,
      'string',
      { ...envelope, v: 2 },
      { ...envelope, extra: 'field' },
      { ...envelope, iv: 'not base64!' },
      { ...envelope, iv: b64u.encode(new Uint8Array(8)) },
      { ...envelope, ek: b64u.encode(new Uint8Array(100)) },
    ]
    for (const input of bad) expect(() => decrypt(recipient, input)).toThrow('decryption failed')
  })

  it('enforces the plaintext size limit and validates the public key', () => {
    expect(() => encrypt(recipient, new Uint8Array(MAX_PLAINTEXT_BYTES + 1))).toThrow('plaintext too large')
    expect(() => encrypt({ kid: recipient.kid, publicKey: new Uint8Array(32) }, text('x'))).toThrow()
  })

  it('restores the same key pair from the 32-byte secret (persistent deployments)', () => {
    const restored = hybridKeyPairFromSecret(recipient.secretKey)
    expect(restored.kid).toBe(recipient.kid)
    expect(b64u.encode(restored.publicKey)).toBe(b64u.encode(recipient.publicKey))
    const envelope: Envelope = encrypt(recipient, text('persisted'))
    expect(new TextDecoder().decode(decrypt(restored, envelope))).toBe('persisted')
    expect(() => hybridKeyPairFromSecret(new Uint8Array(16))).toThrow()
  })
})
