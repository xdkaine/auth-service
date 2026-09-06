# syntax=docker/dockerfile:1.6
# Standalone auth-service build. Context is this repository root.
FROM node:22-alpine AS builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY prisma.config.ts ./
COPY prisma ./prisma
RUN npx prisma generate
COPY tsconfig.json ./
COPY eslint.config.mjs ./
COPY scripts ./scripts
COPY src ./src
RUN npx prisma generate && npm run build

# Operator-only image: Prisma CLI and immutable migration history never enter
# the application runner. No migration executes during image build/startup.
FROM node:22-alpine AS migration-tool
WORKDIR /app
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/prisma ./prisma
COPY --from=builder /app/prisma.config.ts ./prisma.config.ts
ENTRYPOINT ["./node_modules/.bin/prisma"]
CMD ["--help"]

# The builder retains devDependencies for lint/test/tsc. Prune only the copy
# used by the application runner.
FROM builder AS pruned
RUN npm prune --omit=dev

FROM node:22-alpine AS runner
ENV NODE_ENV=production
WORKDIR /app
RUN addgroup -S -g 1001 authsvc && adduser -S -u 1001 authsvc -G authsvc
COPY --from=pruned /app/node_modules ./node_modules
COPY --from=pruned /app/dist ./dist
RUN --mount=type=bind,source=scripts/check-runtime-image.mjs,target=/tmp/check-runtime-image.mjs \
    node /tmp/check-runtime-image.mjs /app auth
USER 1001:1001
EXPOSE 3003
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:3003/healthz || exit 1
CMD ["node", "dist/index.js"]
