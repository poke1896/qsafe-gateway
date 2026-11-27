# syntax=docker/dockerfile:1.7
# Base images are pinned by digest (immutable); Dependabot proposes updates.

# ---- build: full toolchain, never shipped ----
FROM node:22-alpine@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
COPY web ./web
COPY scripts/build-web.ts ./scripts/
RUN npm run build \
 && npm prune --omit=dev --ignore-scripts

# ---- runtime: distroless = no shell, no package manager, runs as non-root (uid 65532) ----
FROM gcr.io/distroless/nodejs22-debian13:nonroot@sha256:c73ddeb03e1dc2d579aa111c83d6699c6b8b487e35c0c631d4a3a20229fc25ee
LABEL org.opencontainers.image.source="https://github.com/poke1896/qsafe-gateway" \
      org.opencontainers.image.description="OAuth2/JWKS API with hybrid post-quantum encryption (X-Wing)" \
      org.opencontainers.image.licenses="MIT"
WORKDIR /app
ENV NODE_ENV=production \
    PORT=8080
COPY --from=build --chown=nonroot:nonroot /app/package.json ./
COPY --from=build --chown=nonroot:nonroot /app/node_modules ./node_modules
COPY --from=build --chown=nonroot:nonroot /app/dist ./dist
USER nonroot
EXPOSE 8080
# Distroless has no curl/wget: probe with Node itself
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["/nodejs/bin/node", "-e", "fetch('http://127.0.0.1:8080/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
CMD ["dist/server.js"]
