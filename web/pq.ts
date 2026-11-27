// Browser implementation of the envelope format, using WebCrypto for HKDF and
// AES-GCM. It is an independent implementation of src/crypto/hybrid.ts: the
// interoperability test proves both sides agree byte for byte.
import { ml_kem768_x25519 as xwing } from '@noble/post-quantum/hybrid.js'

export const HYBRID_ALG = 'XWING-HKDF-SHA256-A256GCM'
const VERSION = 1

export interface Envelope {
  v: 1
  alg: string
  kid: string
  ek: string
  iv: string
  ct: string
  tag: string
}

const toB64u = (bytes: Uint8Array): string => {
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export const fromB64u = (value: string): Uint8Array => {
  const bin = atob(value.replace(/-/g, '+').replace(/_/g, '/'))
  return Uint8Array.from(bin, (c) => c.charCodeAt(0))
}

const utf8 = (s: string): Uint8Array<ArrayBuffer> => new TextEncoder().encode(s)

export async function sha256Hex(data: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(data)))
  return [...digest].map((b) => b.toString(16).padStart(2, '0')).join('')
}

export interface EncryptResult {
  envelope: Envelope
  timings: { encapsulateMs: number; aeadMs: number }
}

export async function encryptForServer(
  recipient: { kid: string; publicKey: Uint8Array },
  plaintext: Uint8Array,
): Promise<EncryptResult> {
  const t0 = performance.now()
  const { cipherText, sharedSecret } = xwing.encapsulate(recipient.publicKey)
  const t1 = performance.now()

  const ikm = await crypto.subtle.importKey('raw', new Uint8Array(sharedSecret), 'HKDF', false, ['deriveKey'])
  const key = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: utf8(`qsafe-gateway/v${VERSION}/${recipient.kid}`) },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt'],
  )
  const iv = crypto.getRandomValues(new Uint8Array(12))
  const ek = toB64u(cipherText)
  const aad = utf8(`${VERSION}.${HYBRID_ALG}.${recipient.kid}.${ek}`)
  const sealed = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, key, new Uint8Array(plaintext)),
  )
  const t2 = performance.now()

  return {
    envelope: {
      v: VERSION,
      alg: HYBRID_ALG,
      kid: recipient.kid,
      ek,
      iv: toB64u(iv),
      ct: toB64u(sealed.slice(0, -16)),
      tag: toB64u(sealed.slice(-16)),
    },
    timings: { encapsulateMs: t1 - t0, aeadMs: t2 - t1 },
  }
}
