import { serve } from '@hono/node-server'
import { buildDeps, createApp } from './gateway.js'
import { loadConfig } from './config.js'

const config = loadConfig()
const app = createApp(await buildDeps(config))

const server = serve({ fetch: app.fetch, port: config.port, hostname: '0.0.0.0' }, (info) => {
  console.info(JSON.stringify({ event: 'listening', port: info.port, env: config.env, issuer: config.issuer }))
})

// Graceful shutdown so orchestrators (Docker, Kubernetes) can drain connections
for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => {
    server.close(() => process.exit(0))
    setTimeout(() => process.exit(1), 10_000).unref()
  })
}
