// Vercel entry point (Node.js runtime, Web-standard handlers). Keys must come from
// env vars here: serverless instances do not share memory, so generated keys would
// differ per instance and tokens would randomly fail verification.
import { handle } from 'hono/vercel'
import { buildDeps, createApp } from '../src/app.js'
import { loadConfig } from '../src/config.js'

const config = loadConfig()
if (config.env === 'production' && (!config.signingKeysJwks || !config.hybridSecretKey)) {
  throw new Error('SIGNING_KEYS_JWKS and HYBRID_SECRET_KEY are required for serverless deployments')
}

const handler = handle(createApp(await buildDeps(config)))

export const GET = handler
export const POST = handler
export const OPTIONS = handler
