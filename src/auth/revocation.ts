/**
 * Denylist of revoked token ids (jti). Entries are kept only until the token
 * would have expired anyway, so memory stays bounded by the token TTL.
 * A multi-instance deployment would back this with Redis or similar.
 */
export class RevocationList {
  private readonly revoked = new Map<string, number>()
  private static readonly MAX_ENTRIES = 100_000

  constructor(private readonly now: () => number = Date.now) {}

  revoke(jti: string, expiresAtSeconds: number): void {
    this.sweep()
    if (this.revoked.size >= RevocationList.MAX_ENTRIES) throw new Error('revocation list full')
    this.revoked.set(jti, expiresAtSeconds * 1000)
  }

  isRevoked(jti: string): boolean {
    const until = this.revoked.get(jti)
    return until !== undefined && until > this.now()
  }

  private sweep(): void {
    const t = this.now()
    for (const [jti, until] of this.revoked) if (until <= t) this.revoked.delete(jti)
  }
}
