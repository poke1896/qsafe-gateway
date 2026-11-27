// Generates persistent key material for deployments. Prints to stdout only:
// paste the values into your secret manager (GitHub/Vercel secrets), never into git.
import { generateSigningJwk } from '../src/keys/signingKeys.js'
import { generateHybridKeyPair } from '../src/crypto/hybrid.js'
import { b64u } from '../src/crypto/encoding.js'

const signing = await generateSigningJwk()
const hybrid = generateHybridKeyPair()

console.log(`SIGNING_KEYS_JWKS='${JSON.stringify([signing])}'`)
console.log(`HYBRID_SECRET_KEY=${b64u.encode(hybrid.secretKey)}`)
console.error(`# hybrid key id: ${hybrid.kid}`)
