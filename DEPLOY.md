# Deploying PluginGuard (free tier)

PluginGuard is two services that both need public HTTPS:

- **analyzer** — Spring Boot static-analysis API (Docker). Stateless; the dynamic sandbox,
  CVE lookup and reputation lists stay **off** (they need Docker/network and aren't used here).
- **web** — Next.js 16 dashboard (Docker). The browser calls the analyzer **directly**, so the
  analyzer must be public and on HTTPS, and its CORS must allow the web origin.

## Option A — Render (one Blueprint, recommended)

The repo ships [`render.yaml`](./render.yaml).

1. Push the repo to GitHub.
2. Render Dashboard → **New → Blueprint** → pick the repo. Render builds both services from their
   Dockerfiles and gives each automatic HTTPS.
3. If Render appended a random suffix to either hostname (only when the name is already taken
   globally), update the two cross-URLs in `render.yaml` to the real URLs and redeploy. Order
   matters: `NEXT_PUBLIC_API_URL` is **baked at build time**, so the web service must *rebuild*
   after a change, not just restart.

**Verify:** open the web URL → **Demo report** loads → drag in a sample `.jar` → report renders.
`GET https://<analyzer>.onrender.com/api/health` should return `{"status":"ok",...}`.

**Free-tier caveats**
- 512 MB / 0.1 CPU; services sleep after ~15 min idle and take ~1 min (+ Spring Boot startup) to
  wake — the first request after idle is slow. 750 instance-hours/month/workspace.
- Reports live in memory (`ScanStore`, 500 max) and are **lost on every spin-down**, so a shared
  `/report/{id}` link breaks once the analyzer sleeps. The uploader still sees their own report
  (it's cached in `sessionStorage`).
- A big/complex jar is CPU-heavy on 0.1 CPU. There is **no rate limiting** on the public upload
  endpoint — fine for a demo, add one before promoting it widely.

## Option B — Cloud Run (analyzer) + Vercel (web)

Better quotas and scale-to-zero, but needs a GCP billing card and two platforms.

1. **Analyzer → Cloud Run:** `gcloud run deploy pluginguard-analyzer --source ./analyzer
   --allow-unauthenticated --memory 512Mi --region <region>`. Note the assigned HTTPS URL.
2. **Web → Vercel:** import the repo, set **Root Directory = `web`**, and add env
   `NEXT_PUBLIC_API_URL = https://<your-cloud-run-url>`. Deploy; note the Vercel URL.
3. **CORS:** set the analyzer's `PLUGINGUARD_CORS_ALLOWEDORIGINS` to the Vercel URL and redeploy
   (`gcloud run services update pluginguard-analyzer --update-env-vars PLUGINGUARD_CORS_ALLOWEDORIGINS=https://<vercel-url>`).

## Before going beyond a demo

- **Persistence:** swap the in-memory `ScanStore` for PostgreSQL so report links survive restarts.
- **Abuse protection:** rate-limit / size-limit `POST /api/scan`.
- **Optional layers:** the CVE, reputation and sandbox features stay off here; the sandbox in
  particular needs a Docker daemon and can't run on these free PaaS tiers.
