import { createHash, timingSafeEqual } from 'node:crypto'

export const SCOPES = ['profile:read', 'messages:write', 'keys:rotate'] as const
export type Scope = (typeof SCOPES)[number]

export interface Client {
  id: string
  /** SHA-256 of the secret: the plaintext secret is never kept in memory after startup. */
  secretHash: Buffer
  allowedScopes: readonly Scope[]
}

const sha256 = (value: string): Buffer => createHash('sha256').update(value, 'utf8').digest()

export function buildClients(secrets: { reader: string; admin: string; playground?: string }): Map<string, Client> {
  const clients: Client[] = [
    { id: 'demo-reader', secretHash: sha256(secrets.reader), allowedScopes: ['profile:read', 'messages:write'] },
    { id: 'demo-admin', secretHash: sha256(secrets.admin), allowedScopes: [...SCOPES] },
  ]
  // Public sandbox client for the browser playground: its secret is intentionally
  // published, so it only ever gets the two low-privilege scopes.
  if (secrets.playground) {
    clients.push({ id: 'playground', secretHash: sha256(secrets.playground), allowedScopes: ['profile:read', 'messages:write'] })
  }
  return new Map(clients.map((c) => [c.id, c]))
}

// Compared even for unknown client ids so response time does not reveal which ids exist
const DUMMY_HASH = sha256('qsafe-gateway-unknown-client')

/** Constant-time client authentication: hashing both sides gives equal-length buffers. */
export function authenticateClient(clients: Map<string, Client>, id: string, secret: string): Client | undefined {
  const client = clients.get(id)
  const matches = timingSafeEqual(sha256(secret), client?.secretHash ?? DUMMY_HASH)
  return client && matches ? client : undefined
}

/** Returns the granted scopes, or undefined if anything outside the client's allowance was requested. */
export function grantScopes(client: Client, requested: string | undefined): Scope[] | undefined {
  if (!requested?.trim()) return [...client.allowedScopes]
  const asked = [...new Set(requested.trim().split(/\s+/))]
  return asked.every((s) => (client.allowedScopes as readonly string[]).includes(s)) ? (asked as Scope[]) : undefined
}
