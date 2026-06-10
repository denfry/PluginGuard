# --- Dependencies ---
FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

# --- Build (Next.js standalone output) ---
FROM node:22-alpine AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# The analyzer URL the Next server proxies /api/* to (see next.config.ts). Resolved into
# the route manifest at build time, NOT exposed to the browser. On Render this is supplied
# automatically as a build arg from the service's ANALYZER_URL environment variable.
ARG ANALYZER_URL=http://localhost:8080
ENV ANALYZER_URL=$ANALYZER_URL
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

# --- Run ---
FROM node:22-alpine AS run
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
RUN addgroup -g 1001 nodejs && adduser -S -u 1001 nextjs
USER nextjs

COPY --from=build /app/public ./public
COPY --from=build --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=build --chown=nextjs:nodejs /app/.next/static ./.next/static

EXPOSE 3000
ENV PORT=3000
ENV HOSTNAME=0.0.0.0
CMD ["node", "server.js"]
