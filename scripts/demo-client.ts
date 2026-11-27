// End-to-end demo: get a token, fetch the server's post-quantum public key,
// encrypt a message locally with X-Wing + AES-256-GCM, and send it.
//   npm run dev            (terminal 1)
//   npm run demo           (terminal 2)
// Env: BASE_URL, CLIENT_ID, CLIENT_SECRET, MESSAGE
import { createHash } from 'node:crypto'
import { encrypt } from '../src/crypto/hybrid.js'
import { b64u } from '../src/crypto/encoding.js'

const base = process.env['BASE_URL'] ?? 'http://localhost:8080'
const clientId = process.env['CLIENT_ID'] ?? 'demo-reader'
const clientSecret = process.env['CLIENT_SECRET'] ?? 'dev-only-reader-secret-change-me-0001'
const message = process.env['MESSAGE'] ?? 'Harvest now, decrypt later? Not this message.'

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${base}${path}`, init)
  const body = (await res.json()) as T
  if (!res.ok) throw new Error(`${path} -> ${res.status} ${JSON.stringify(body)}`)
  return body
}

const basic = Buffer.from(`${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`).toString('base64')
const { access_token, expires_in, scope } = await call<{ access_token: string; expires_in: number; scope: string }>(
  '/oauth/token',
  {
    method: 'POST',
    headers: { authorization: `Basic ${basic}`, 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'client_credentials', scope: 'messages:write' }),
  },
)
console.log(`1. access token (ES256, ${expires_in}s, scope="${scope}")`)

const pk = await call<{ kid: string; alg: string; publicKey: string }>('/pq/public-key')
console.log(`2. server public key ${pk.kid} (${pk.alg}, ${b64u.decode(pk.publicKey).length} bytes)`)

const envelope = encrypt({ kid: pk.kid, publicKey: b64u.decode(pk.publicKey) }, new TextEncoder().encode(message))
console.log(`3. encrypted locally: KEM ciphertext ${b64u.decode(envelope.ek).length} bytes`)

const receipt = await call<{ received: boolean; bytes: number; sha256: string }>('/api/messages', {
  method: 'POST',
  headers: { authorization: `Bearer ${access_token}`, 'content-type': 'application/json' },
  body: JSON.stringify(envelope),
})
const expected = createHash('sha256').update(message).digest('hex')
console.log(`4. server decrypted ${receipt.bytes} bytes, hash ${receipt.sha256 === expected ? 'matches' : 'MISMATCH'}`)
