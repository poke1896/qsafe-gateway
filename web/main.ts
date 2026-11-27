import { encryptForServer, fromB64u, sha256Hex, type Envelope } from './pq.js'

// ---------- tiny DOM helpers (textContent only: nothing from the network is parsed as HTML) ----------
const $ = <T extends HTMLElement = HTMLElement>(id: string): T => {
  const el = document.getElementById(id)
  if (!el) throw new Error(`#${id} missing`)
  return el as T
}
const show = (id: string) => $(id).removeAttribute('hidden')
function span(text: string, className?: string): HTMLSpanElement {
  const s = document.createElement('span')
  s.textContent = text
  if (className) s.className = className
  return s
}
function setMeta(id: string, parts: Array<string | [string, 'ok' | 'bad']>) {
  const el = $(id)
  el.replaceChildren(...parts.map((p) => (typeof p === 'string' ? document.createTextNode(p) : span(p[0], p[1]))))
}
const json = (value: unknown) => JSON.stringify(value, null, 2)
const enc = new TextEncoder()
const b64uJson = (value: unknown) =>
  btoa(String.fromCharCode(...enc.encode(JSON.stringify(value)))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
const decodePart = (part: string) => JSON.parse(new TextDecoder().decode(fromB64u(part))) as Record<string, unknown>

async function withBusy<T>(button: HTMLButtonElement, fn: () => Promise<T>): Promise<T | undefined> {
  const label = button.textContent
  button.classList.add('busy')
  button.textContent = 'Working…'
  try {
    return await fn()
  } catch (error) {
    console.error(error)
    alertInline(button, error instanceof Error ? error.message : 'Request failed')
    return undefined
  } finally {
    button.classList.remove('busy')
    button.textContent = label
  }
}
function alertInline(near: HTMLElement, message: string) {
  const p = document.createElement('p')
  p.className = 'meta bad'
  p.textContent = message
  near.after(p)
  setTimeout(() => p.remove(), 6000)
}

// ---------- API ----------
interface PlaygroundConfig { clientId: string; clientSecret: string; scope: string }
interface PublicKey { kid: string; alg: string; publicKey: string }

async function api(path: string, init?: RequestInit) {
  const res = await fetch(path, init)
  const body = res.headers.get('content-type')?.includes('json') ? await res.json() : null
  return { status: res.status, body: body as Record<string, unknown> | null }
}

let config: PlaygroundConfig | undefined
let token: string | undefined
let tokenExp = 0
let serverKey: PublicKey | undefined

async function getServerKey(): Promise<{ kid: string; publicKey: Uint8Array; raw: PublicKey }> {
  serverKey ??= (await api('/pq/public-key')).body as unknown as PublicKey
  return { kid: serverKey.kid, publicKey: fromB64u(serverKey.publicKey), raw: serverKey }
}

// ---------- Step 1: token ----------
async function requestToken() {
  config ??= (await api('/playground/config')).body as unknown as PlaygroundConfig
  const basic = btoa(`${encodeURIComponent(config.clientId)}:${encodeURIComponent(config.clientSecret)}`)
  const res = await api('/oauth/token', {
    method: 'POST',
    headers: { authorization: `Basic ${basic}`, 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'client_credentials', scope: config.scope }),
  })
  if (res.status !== 200 || !res.body) throw new Error(`Token request failed (${res.status})`)
  token = String(res.body['access_token'])
  const [h, p, s] = token.split('.') as [string, string, string]
  const header = decodePart(h)
  const payload = decodePart(p)
  tokenExp = Number(payload['exp'])

  $('jwt-raw').replaceChildren(span(h, 'h'), document.createTextNode('.'), span(p, 'p'), document.createTextNode('.'), span(s, 's'))
  $('jwt-header').textContent = json(header)
  $('jwt-payload').textContent = json(payload)
  show('out-token')
  $('step1').classList.add('done')
  tickExpiry(String(header['kid']))
  for (const id of ['btn-verify', 'btn-encrypt']) $<HTMLButtonElement>(id).disabled = false
  document.querySelectorAll<HTMLButtonElement>('.attack').forEach((b) => (b.disabled = false))
}

let timer: number | undefined
function tickExpiry(kid: string) {
  window.clearInterval(timer)
  const render = () => {
    const left = Math.max(0, tokenExp - Math.floor(Date.now() / 1000))
    setMeta('jwt-meta', [
      'Signed with ES256 by key ',
      [kid.slice(0, 12) + '…', 'ok'],
      left > 0 ? ` · expires in ${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')}` : ' · ',
      ...(left > 0 ? [] : [['expired: request a new one', 'bad'] as [string, 'bad']]),
    ])
  }
  render()
  timer = window.setInterval(render, 1000)
}

// ---------- Step 2: JWKS + protected call ----------
async function verify() {
  if (!token) return
  const kid = String(decodePart(token.split('.')[0] ?? '')['kid'])
  const jwks = (await api('/.well-known/jwks.json')).body as { keys: Array<Record<string, unknown>> }
  $('jwks').textContent = json({
    keys: jwks.keys.map((k) => (k['kid'] === kid ? { '// matches token kid': '✓', ...k } : k)),
  })
  const me = await api('/api/me', { headers: { authorization: `Bearer ${token}` } })
  show('out-verify')
  if (me.status === 200) {
    $('step2').classList.add('done')
    setMeta('verify-meta', ['GET /api/me → ', ['200 OK', 'ok'], ` as ${String(me.body?.['sub'])}. No private key is ever published: only kty, crv, x, y.`])
  } else {
    setMeta('verify-meta', ['GET /api/me → ', [`${me.status}`, 'bad'], ' (token expired? get a new one)'])
  }
}

// ---------- Step 3: post-quantum encryption ----------
async function encryptAndSend() {
  if (!token) return
  const message = $<HTMLTextAreaElement>('message').value
  const key = await getServerKey()
  const plaintext = enc.encode(message)
  const { envelope, timings } = await encryptForServer(key, plaintext)

  const stats = [
    [`${key.publicKey.length} B`, 'X-Wing public key'],
    [`${fromB64u(envelope.ek).length} B`, 'KEM ciphertext'],
    [`${timings.encapsulateMs.toFixed(1)} ms`, 'encapsulation'],
    [`${timings.aeadMs.toFixed(1)} ms`, 'HKDF + AES-GCM'],
  ]
  $('pq-stats').replaceChildren(
    ...stats.map(([value, label]) => {
      const d = document.createElement('div')
      d.className = 'stat'
      const b = document.createElement('b')
      b.textContent = value ?? ''
      d.append(b, span(label ?? ''))
      return d
    }),
  )
  const short = (v: string) => (v.length > 64 ? `${v.slice(0, 64)}… (${v.length} chars)` : v)
  $('envelope').textContent = json({ ...envelope, ek: short(envelope.ek), ct: short(envelope.ct) })
  show('out-encrypt')

  const res = await sendEnvelope(envelope)
  const local = await sha256Hex(plaintext)
  if (res.status === 200 && res.body?.['sha256'] === local) {
    $('step3').classList.add('done')
    setMeta('encrypt-meta', [
      'Server decrypted ',
      [`${String(res.body['bytes'])} bytes`, 'ok'],
      ' and returned SHA-256 ',
      [`${local.slice(0, 16)}…`, 'ok'],
      ', identical to the hash computed here. The plaintext itself is never sent back.',
    ])
  } else {
    setMeta('encrypt-meta', ['Server answered ', [`${res.status}`, 'bad'], ' (token expired? get a new one)'])
  }
}

const sendEnvelope = (envelope: unknown) =>
  api('/api/messages', {
    method: 'POST',
    headers: { authorization: `Bearer ${token ?? ''}`, 'content-type': 'application/json' },
    body: JSON.stringify(envelope),
  })

// ---------- Attack lab ----------
const escalated = (payload: Record<string, unknown>) => ({ ...payload, scope: 'profile:read messages:write keys:rotate' })
const rotate = (forged: string) => api('/admin/keys/rotate', { method: 'POST', headers: { authorization: `Bearer ${forged}` } })

function flipFirstBit(value: string): string {
  const bytes = fromB64u(value)
  bytes[0] = (bytes[0] ?? 0) ^ 1
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

const attacks: Record<string, () => Promise<{ status: number; body: Record<string, unknown> | null }>> = {
  async none() {
    const [h, p] = (token ?? '').split('.') as [string, string]
    const header: Record<string, unknown> = { ...decodePart(h), alg: 'none' }
    delete header['kid']
    return rotate(`${b64uJson(header)}.${b64uJson(escalated(decodePart(p)))}.`)
  },
  async hs256() {
    const [h, p] = (token ?? '').split('.') as [string, string]
    const kid = decodePart(h)['kid']
    const jwks = (await api('/.well-known/jwks.json')).body as { keys: unknown[] }
    const publicJwk = jwks.keys[0]
    const signingInput = `${b64uJson({ alg: 'HS256', kid, typ: 'at+jwt' })}.${b64uJson(escalated(decodePart(p)))}`
    const hmac = await crypto.subtle.importKey('raw', enc.encode(JSON.stringify(publicJwk)), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
    const sig = new Uint8Array(await crypto.subtle.sign('HMAC', hmac, enc.encode(signingInput)))
    return rotate(`${signingInput}.${btoa(String.fromCharCode(...sig)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')}`)
  },
  async tamper() {
    const [h, p, s] = (token ?? '').split('.') as [string, string, string]
    return rotate(`${h}.${b64uJson(escalated(decodePart(p)))}.${s}`)
  },
  async scope() {
    return rotate(token ?? '')
  },
  async ciphertext() {
    const { envelope } = await encryptForServer(await getServerKey(), enc.encode('wire transfer: $10'))
    return sendEnvelope({ ...envelope, ct: flipFirstBit(envelope.ct) })
  },
  async kem() {
    const key = await getServerKey()
    const a = await encryptForServer(key, enc.encode('message A'))
    const b = await encryptForServer(key, enc.encode('message B'))
    const spliced: Envelope = { ...a.envelope, ek: b.envelope.ek }
    return sendEnvelope(spliced)
  },
}

const attackMap = new Map(Object.entries(attacks))

async function runAttack(button: HTMLButtonElement) {
  const name = button.dataset['attack'] ?? ''
  const attack = Object.hasOwn(attacks, name) ? attackMap.get(name) : undefined
  const verdict = button.querySelector<HTMLElement>('.verdict')
  if (!attack || !verdict) return
  verdict.textContent = 'sending…'
  button.classList.remove('blocked', 'passed')
  const res = await attack().catch(() => ({ status: 0, body: null }))
  const blocked = res.status >= 400 && res.status < 500
  button.classList.add(blocked ? 'blocked' : 'passed')
  verdict.textContent = blocked
    ? `BLOCKED · ${res.status} ${String(res.body?.['error'] ?? 'edge firewall')}`
    : res.status === 0
      ? 'network error'
      : `NOT BLOCKED · ${res.status}`
}

// ---------- wire up ----------
document.addEventListener('DOMContentLoaded', () => {
  const tokenBtn = $<HTMLButtonElement>('btn-token')
  tokenBtn.addEventListener('click', () => void withBusy(tokenBtn, requestToken))
  const verifyBtn = $<HTMLButtonElement>('btn-verify')
  verifyBtn.addEventListener('click', () => void withBusy(verifyBtn, verify))
  const encryptBtn = $<HTMLButtonElement>('btn-encrypt')
  encryptBtn.addEventListener('click', () => void withBusy(encryptBtn, encryptAndSend))
  document.querySelectorAll<HTMLButtonElement>('.attack').forEach((b) => b.addEventListener('click', () => void runAttack(b)))
})
