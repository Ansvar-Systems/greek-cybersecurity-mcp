# ─────────────────────────────────────────────────────────────────────────────
# greek-cybersecurity-mcp — multi-stage Dockerfile
# ─────────────────────────────────────────────────────────────────────────────
# Build:  docker build -t greek-cybersecurity-mcp .
# Run:    docker run --rm -p 3000:3000 greek-cybersecurity-mcp
# ─────────────────────────────────────────────────────────────────────────────

# --- Stage 1: Build TypeScript + native deps ---
FROM node:20-slim AS builder

# Install build tools needed for better-sqlite3 native binding
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 make g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package.json package-lock.json* ./
# Run full install (no --ignore-scripts) so better-sqlite3's postinstall builds the .node binding
RUN npm ci
COPY tsconfig.json ./
COPY src/ src/
RUN npm run build

# --- Stage 2: Production ---
FROM node:20-slim AS production

WORKDIR /app
ENV NODE_ENV=production
ENV NCSA_DB_PATH=/app/data/ncsa.db

# Reuse the builder's node_modules so the better-sqlite3 native binding survives
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist/ dist/
COPY package.json package-lock.json* ./

# DB baked from CI's data/database.db (workflow gunzips database.db.gz from the Release)
COPY data/database.db data/ncsa.db

# Non-root user for security
RUN addgroup --system --gid 1001 mcp && \
    adduser --system --uid 1001 --ingroup mcp mcp && \
    chown -R mcp:mcp /app
USER mcp

# Health check: verify HTTP server responds
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health',r=>{process.exit(r.statusCode===200?0:1)}).on('error',()=>process.exit(1))"

CMD ["node", "dist/src/http-server.js"]
