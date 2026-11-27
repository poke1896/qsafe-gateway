# Threat model (STRIDE)

**Assets:** signing private keys, X-Wing secret key, client secrets, access tokens, encrypted message contents.
**Trust boundaries:** internet → API; CI runner → container registry; registry → runtime.

| Threat | Example attack | Mitigation | Verified by |
|---|---|---|---|
| **Spoofing** | Forged JWT with `alg: none` | Algorithm allowlist (`ES256` only) | `tokens.test.ts` |
| Spoofing | HS256 token keyed with the public JWK (key confusion) | Allowlist + asymmetric key objects only | `tokens.test.ts` |
| Spoofing | Token from another issuer/audience, or an ID token replayed as access token | `iss`, `aud` and `typ: at+jwt` checks | `tokens.test.ts` |
| Spoofing | Client secret brute force | Rate limit per IP, constant-time compare, dummy compare for unknown ids | `app.test.ts` |
| **Tampering** | Editing claims to add `keys:rotate` | ES256 signature over header + payload | `tokens.test.ts` |
| Tampering | Bit-flipping ciphertext, IV, tag or KEM ciphertext | AES-256-GCM authentication; header + KEM ciphertext as AAD | `hybrid.test.ts` |
| Tampering | Malicious image or dependency in the supply chain | SHA-pinned actions, digest-pinned bases, npm registry signatures, cosign signing, SLSA provenance, Dependabot cooldown | CI workflows |
| **Repudiation** | "That key rotation wasn't me" | Structured audit log of rotation with the acting subject; request ids | `app.ts` |
| **Information disclosure** | Private key leaked through JWKS | Public JWK built from an explicit allowlist of members (`kty`, `crv`, `x`, `y`) | `tokens.test.ts` |
| Information disclosure | Error messages as a decryption/verification oracle | Single generic error per class; reasons logged server-side only | `hybrid.test.ts`, `app.test.ts` |
| Information disclosure | Recorded traffic decrypted by a future quantum computer | X-Wing hybrid KEM (ML-KEM-768 + X25519) | `hybrid.test.ts` |
| Information disclosure | Tokens cached by proxies | `Cache-Control: no-store` on token endpoints | `app.test.ts` |
| Information disclosure | Secrets committed to git | gitleaks on full history, `.env` ignored | `security.yml` |
| **Denial of service** | Huge bodies or tokens | 64 KiB body limit, 4 KiB token limit, 32 KiB plaintext limit | `app.test.ts`, `tokens.test.ts` |
| Denial of service | Unbounded revocation list | Entries expire with the token; hard cap | `revocation.ts` |
| **Elevation of privilege** | Reader requests admin scope | Scopes granted only from the client's allowlist | `app.test.ts` |
| Elevation of privilege | Container breakout | Distroless, non-root uid 65532, read-only FS, `--cap-drop ALL`, `no-new-privileges` | `container.yml` |

## Residual risks

- In-memory key storage: a host compromise exposes keys. Production should use a KMS/HSM and sign remotely.
- Per-instance rate limiting and revocation; horizontal scaling needs a shared store.
- ML-KEM implementations are young; the hybrid construction keeps X25519 as a safety net, and the library
  (`@noble/post-quantum`) is pinned and tracked by Dependabot.
