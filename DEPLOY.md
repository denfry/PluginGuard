# Deploying PluginGuard (free tier)

PluginGuard is two services:

- **analyzer** — Spring Boot static-analysis API (Docker). Stateless; the dynamic sandbox,
  CVE lookup and reputation lists stay **off** (they need Docker/network and aren't used here).
- **web** — Next.js 16 dashboard (Docker). The browser only ever calls the **web** app; the Next
  server **proxies `/api/*` to the analyzer** (`next.config.ts` rewrites). So there is no CORS,
  no mixed-content, and no analyzer URL in the client bundle — the only thing to configure is the
  web service's `ANALYZER_URL`.

## Option A — Render (one Blueprint, recommended)

The repo ships [`render.yaml`](./render.yaml).

1. Push the repo to GitHub.
2. Render Dashboard → **New → Blueprint** → pick the repo. Render builds both services from their
   Dockerfiles and gives each automatic HTTPS.
3. `ANALYZER_URL` on the web service is pre-filled with the analyzer's default URL
   (`https://pluginguard-analyzer.onrender.com`). If Render appended a random suffix to the
   analyzer's name (only when the name is already taken globally), set `ANALYZER_URL` to the
   analyzer's real URL and **redeploy the web service** — it's baked into the route manifest at
   build time, so it needs a rebuild, not just a restart.

> The analyzer stays a **public** web service: Render free services can *send* outbound requests
> but cannot *receive* private ones, so the web proxy reaches it over its public URL.

**Verify:** open the web URL → **Demo report** loads → drag in a sample `.jar` → report renders.
Through the proxy, `GET https://<web>.onrender.com/api/health` should return `{"status":"ok",...}`.

**Free-tier caveats**
- 512 MB / 0.1 CPU; services sleep after ~15 min idle and take ~1 min (+ Spring Boot startup) to
  wake — the first request after idle is slow (the proxied call waits for the analyzer to spin up).
  750 instance-hours/month/workspace.
- Reports live in memory (`ScanStore`, 500 max) and are **lost on every spin-down**, so a shared
  `/report/{id}` link breaks once the analyzer sleeps. The uploader still sees their own report
  (it's cached in `sessionStorage`).
- A big/complex jar is CPU-heavy on 0.1 CPU. There is **no rate limiting** on the upload endpoint —
  fine for a demo, add one before promoting it widely.

## Option B — Cloud Run (analyzer) + Vercel (web)

Better quotas and scale-to-zero, but needs a GCP billing card and two platforms.

1. **Analyzer → Cloud Run:** `gcloud run deploy pluginguard-analyzer --source ./analyzer
   --allow-unauthenticated --memory 512Mi --region <region>`. Note the assigned HTTPS URL.
2. **Web → Vercel:** import the repo, set **Root Directory = `web`**, and add env
   `ANALYZER_URL = https://<your-cloud-run-url>` (available at build time, so the proxy target is
   baked into the build). Deploy.
3. No CORS step: the browser only talks to Vercel; Vercel proxies `/api/*` to Cloud Run server-side.

> ⚠️ Vercel caps proxied request bodies (~4.5 MB). The 50 MB upload limit only holds on a self-hosted
> Node server (Render/Cloud Run/Docker). On Vercel, lower the upload limit or front the analyzer
> directly for large jars. This is why Render is the recommended path.

## Before going beyond a demo

- **Persistence:** swap the in-memory `ScanStore` for PostgreSQL so report links survive restarts.
- **Abuse protection:** rate-limit / size-limit the upload path.
- **Optional layers:** the CVE, reputation and sandbox features stay off here; the sandbox in
  particular needs a Docker daemon and can't run on these free PaaS tiers.
