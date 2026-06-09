# PluginGuard

**Deep, risk-based static security analysis for Minecraft plugin `.jar` files.**

Upload a plugin and PluginGuard shows what it *really* does before you install it on your
server: dangerous bytecode calls, network indicators, credential-theft markers, obfuscation,
bundled dependencies and `plugin.yml` validation — distilled into a 0–100 security score, a
verdict and an itemised report.

> ⚠️ **Not a guarantee.** PluginGuard performs *static* analysis and reports **risk**, not proof
> of safety or malice. A clean scan is not a green light, and a high-risk finding is not always
> malicious (e.g. a Discord webhook can be a legitimate logging feature). Always review the
> findings in context.

> 🔒 **The uploaded plugin is never executed.** Bytecode is parsed read-only with ASM, YAML is
> parsed in safe mode, and strings are read from the constant pool. No class is ever loaded into
> the JVM. The upload is discarded after analysis.

---

## What it checks

| Pass | Highlights |
|------|------------|
| **Structure** | Real JAR vs renamed file, native libs (`.dll/.so/.exe/…`), nested JARs, Java-agent manifests, zip-bomb guards |
| **plugin.yml** | name/version/main/api-version, commands, permissions, missing main class, wildcard perms, backdoor-style commands |
| **Bytecode (ASM)** | `Runtime.exec`, `ProcessBuilder`, `URLClassLoader`/`defineClass`, native loading, reflection, sockets, HTTP, crypto, `System.exit` |
| **Strings / IOC** | URLs & Discord/Telegram webhooks, public IPs, shell-command markers, credential-theft paths, base64 blobs |
| **Obfuscation** | Short class/method names, default packages, reflection density, encoded-string density → 0–100 score |
| **Dependencies** | Best-effort SBOM from `pom.properties` + nested JARs |

---

## Architecture

```
web/        Next.js 16 + Tailwind v4 — dark security dashboard (upload, report, demo)
analyzer/   Spring Boot 3.5 (Java 21) — REST API + the static-analysis engine (ASM, SnakeYAML)
sample-plugins/   Synthetic benign & malicious-looking plugins for demo and tests
```

The browser uploads a `.jar` to the analyzer's `POST /api/scan`, which runs the pipeline
synchronously (static analysis is fast) and returns a JSON report. The web app renders it and
caches it by id; a direct visit re-fetches `GET /api/scan/{id}`.

---

## Running locally

**Prerequisites:** JDK 21, Node 20+.

```bash
# 1. Analyzer API (http://localhost:8080)
cd analyzer
./gradlew bootRun

# 2. Web app (http://localhost:3000) — in another terminal
cd web
npm install
npm run dev
```

Open <http://localhost:3000>, drag in a `.jar`, or click **Demo report**.

The web app reads the analyzer URL from `NEXT_PUBLIC_API_URL` (default `http://localhost:8080`).

### With Docker

```bash
docker compose up --build
# web → http://localhost:3000   analyzer → http://localhost:8080
```

---

## Sample plugins

```bash
cd sample-plugins
./build.ps1      # Windows  (or ./build.sh on macOS/Linux/Git-Bash)
```

This produces `BenignChat-1.2.0.jar` (scores high) and `FreeRanks-2.3.jar` (a *simulated*
malware sample — its hostile method is never called and targets are placeholders; do not run it
on a real server). Drag either into the scanner to see a report.

---

## API

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/scan` | multipart `file` → full `ScanResult` JSON |
| `GET`  | `/api/scan/{id}` | a previously generated report (in-memory, ephemeral) |
| `GET`  | `/api/demo` | a fixed illustrative report |
| `GET`  | `/api/health` | liveness |

```bash
curl -F "file=@sample-plugins/FreeRanks-2.3.jar" http://localhost:8080/api/scan
```

---

## Tests

```bash
cd analyzer && ./gradlew test
```

The suite builds synthetic JARs in memory (ASM) and asserts that a benign plugin scores well,
a malicious one is flagged Critical with the expected findings, a non-JAR upload is caught, and
a bundled native library is reported.

---

## Roadmap (not in this version)

Sandbox execution (fake Paper server, network/file monitoring) · CVE lookup for dependencies ·
GitHub/SHA provenance + Sigstore signatures · PostgreSQL + a job queue · public report database ·
API keys · browser extension / Discord bot / GitHub Action / "Scanned by PluginGuard" badge.
