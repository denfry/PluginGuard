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
  wake. The `keep-warm` workflow (below) hides this during a daily window; outside it, the first
  request is slow (the proxied call waits for the analyzer to spin up).
- By default reports live in memory (`ScanStore`, 500 max) and are **lost on every spin-down**, so a
  shared `/report/{id}` link breaks once the analyzer sleeps. Enable Postgres persistence (below) to
  keep them. The uploader always sees their own report (cached in `sessionStorage`).
- A big/complex jar is CPU-heavy on 0.1 CPU. `POST /api/scan` is **rate-limited per client IP**
  (default 10/min — `PLUGINGUARD_RATELIMIT_SCANSPERMINUTE`; report polling and health are never
  limited), but each scan is still heavy, so watch it under load.

### Keeping the services warm (the 15-min spin-down)

The repo ships [`.github/workflows/keep-warm.yml`](./.github/workflows/keep-warm.yml) — a scheduled
GitHub Action that pings `/api/health` every 10 min during a daily window, so both services stay
responsive when people actually use the app (one ping to the web warms the analyzer too, via the
proxy). It deliberately does **not** run 24/7: Render free is **750 instance-hours/month per
workspace**, and two always-on services would burn ~1460 h and get suspended. The default window
(`08:00–17:59 UTC`, ~608 h/month) stays well under budget — widen/narrow the cron in that file, keeping
`window_hours × 2 × 30.4` comfortably under 750.

After the first push, enable it under the repo's **Actions** tab if prompted. If Render appended a
suffix to a service name, set repo **Variables** `WEB_URL` / `ANALYZER_URL` (Settings → Secrets and
variables → Actions). GitHub's scheduler is best-effort (runs can be delayed) and auto-disables after
60 days with no commits; for a rock-solid pinger use an external uptime monitor (cron-job.org,
UptimeRobot) pointed at `<web-url>/api/health` on the same window.

### Durable reports (optional Postgres)

By default reports are in-memory and clear when the analyzer sleeps or restarts. To make
`/report/{id}` links durable, point the analyzer at a PostgreSQL database — each report is stored as
the same JSON the API returns and read back on demand (the `reports` table is created on first boot
and capped at the newest 1000 rows).

Use a **persistent** free Postgres. [Neon](https://neon.tech) fits well (its free tier runs
indefinitely); Render's own free Postgres is **deleted after 30 days**, so avoid it for anything you
want to keep.

1. Create a free Neon project and copy its **JDBC** connection details.
2. On the **analyzer** service (Render → Environment) set:
   - `PLUGINGUARD_PERSISTENCE` = `jdbc`
   - `SPRING_DATASOURCE_URL` = `jdbc:postgresql://<host>/<db>?sslmode=require`
   - `SPRING_DATASOURCE_USERNAME` = `<user>`
   - `SPRING_DATASOURCE_PASSWORD` = `<password>`
3. Redeploy the analyzer.

Leaving `PLUGINGUARD_PERSISTENCE=memory` (or unset) runs with no database — nothing else changes.
Verified end-to-end locally: a report scanned before an analyzer restart is still served by
`GET /api/scan/{id}` afterwards.

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

- **Persistence:** reports are in-memory by default; enable Postgres (see *Durable reports* above) so
  `/report/{id}` links survive restarts.
- **Abuse protection:** `POST /api/scan` is per-IP rate-limited (configurable); add a CDN/WAF or
  stricter limits for heavier exposure.
- **Optional layers:** the CVE, reputation and sandbox features stay off here; the sandbox in
  particular needs a Docker daemon and can't run on these free PaaS tiers.
