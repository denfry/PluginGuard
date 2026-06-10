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

PluginGuard uses **defense-in-depth**: many independent passes, plus a correlation engine that
treats a *combination* of capabilities as far more serious than any one of them alone.

| Pass | Highlights |
|------|------------|
| **Structure** | Real JAR vs renamed file, native libs (`.dll/.so/.exe/…`), nested JARs, Java-agent manifests, external manifest `Class-Path`, zip-bomb guards |
| **Nested JARs** | Bundled/shaded `.jar`/`.zip`/`.war` are unpacked and analyzed **recursively** (to a depth limit); findings are attributed with the jar-chain path (`lib.jar!/com/evil/X`) |
| **plugin.yml** | name/version/main/api-version, commands, permissions, missing main class, wildcard perms, backdoor-style commands, `load: STARTUP`/`loadbefore`, remote `libraries:`, dependency count |
| **Bytecode (ASM)** | Process exec, dynamic/remote class loading (incl. `MethodHandles.Lookup.defineClass`, instrumentation, **JNDI lookup**), native loading, reflection + `setAccessible`/`jdk.internal`, **scripting engines** (JS/Groovy/BeanShell/…), **deserialization** (`ObjectInputStream`/XStream), AWT `Robot`/clipboard/desktop, low-level networking (UDP/multicast/RMI), `SecurityManager` removal, **time-bomb** heuristic, `System.exit`/`halt` |
| **invokedynamic** | Bootstrap methods + method-handle arguments are captured; non-standard bootstraps are flagged as obfuscation, and `Foo::dangerous` method references are matched like direct calls |
| **Reflection resolution** | Resolves string operands of `Class.forName("…")` / `getMethod("…")` to apply the dangerous-API rules to reflectively-named targets |
| **Decode & rescan** | Base64/hex (and single-byte XOR) blobs are decoded within strict limits; an embedded class (`CAFEBABE`) is fed back through ASM, embedded archives/native binaries and hidden URLs/shell strings are flagged |
| **Embedded payloads** | Every resource's **raw bytes** are checked against file magic regardless of extension (class/zip/PE/ELF/Mach-O disguised as `.png/.dat/…`), plus an entropy check for encrypted/packed blobs |
| **Strings / IOC** | URLs & Discord/Telegram webhooks, public IPs, shell-command markers, credential-theft paths, base64 blobs |
| **Obfuscation** | Short class/method names, default packages, reflection density, encoded-string density → 0–100 score |
| **Correlation (combo)** | Raises Critical/High when capabilities combine: network + class loading = remote loader; class loading + crypto/encoded = encrypted payload loader; reflection + process; deserialization + network; native + process = dropper; scripting + network; credential paths + exfiltration = stealer |
| **Dependencies** | Best-effort SBOM from `pom.properties` + nested JARs |
| **CVE check** *(opt-in)* | Queries OSV.dev for known vulnerabilities in bundled `groupId:artifactId:version` dependencies; severity from CVSS/GHSA, links to the advisory; disk cache + offline fallback |
| **Reputation** *(opt-in)* | Matches the JAR's (and nested JARs') SHA-256 against pull-able known-malicious (Critical) / known-good (info) lists |
| **Dynamic sandbox** *(opt-in)* | **Executes** the plugin in a hardened, non-root, `--network none` Docker container with an instrumented JVM + mock Paper harness; records real process/socket/file/reflection/`defineClass` behavior, cross-checks it against the static findings (confirmed vs. *runtime-only*), and floors the verdict on dynamic Critical/High evidence |

> 🧪 **Honest residual risk.** Deciding whether an arbitrary program is malicious is undecidable
> (Rice's theorem). Static analysis can be defeated by genuinely dynamic code (targets built only
> at runtime), strong encryption of payloads, and logic gated on the environment. The dynamic
> sandbox narrows that gap but has its own blind spots: it only sees code paths it triggers, and
> malware can detect the sandbox and lie low (sandbox evasion). PluginGuard's goal is to make
> hiding a backdoor *expensive and noisy*, not to prove safety. The report always states **risk**,
> never a "safe" verdict.

---

## Architecture

```
web/        Next.js 16 + Tailwind v4 — dark security dashboard (upload, report, demo)
analyzer/   Spring Boot 3.5 (Java 21) — REST API + the static-analysis engine (ASM, SnakeYAML)
analyzer/sandbox-runtime/   Plain Java + ASM — the JVM agent + mock Bukkit harness that runs
                            INSIDE the isolated container (kept out of the analyzer's own classpath)
sample-plugins/   Synthetic benign & malicious-looking plugins for demo and tests
```

The browser uploads a `.jar` to the web app's own `/api/scan`, which the Next server proxies to the
analyzer's `POST /api/scan` (so the browser stays same-origin — no CORS, no mixed-content). The
analyzer runs the static pipeline synchronously (it is fast) and returns a JSON report; the web app
renders it and caches it by id, and a direct visit re-fetches `GET /api/scan/{id}`. When the dynamic
sandbox is enabled, the static report comes back immediately with a `sandbox` section in
`PENDING`/`RUNNING`, and the page polls `GET /api/scan/{id}` until the asynchronous run reaches
`COMPLETED`.

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

The web app proxies `/api/*` to the analyzer at `ANALYZER_URL` (default `http://localhost:8080`), so
the browser only ever calls the web app's own origin — no CORS configuration needed.

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
| `GET`  | `/api/scan/{id}` | a previously generated report (in-memory by default; durable with Postgres — see [DEPLOY.md](DEPLOY.md)) |
| `GET`  | `/api/demo` | a fixed illustrative report |
| `GET`  | `/api/health` | liveness |

```bash
curl -F "file=@sample-plugins/FreeRanks-2.3.jar" http://localhost:8080/api/scan
```

---

## Dynamic sandbox (Phase 3, opt-in)

The sandbox **executes the uploaded plugin** to observe what it actually does — catching
reflection-built, decoded or otherwise runtime-only behavior that static analysis cannot see. It is
**off by default** and the *static* analyzer never runs the jar; only this opt-in layer does, and
only inside isolation.

How it works:

- **Hardened container** — each run is a throw-away Docker container: non-root (`nobody`),
  `--read-only` root fs, `--cap-drop ALL`, `--security-opt no-new-privileges`, pids/cpu/memory caps,
  and `--network none` so every egress attempt is *logged but cannot leave the host*.
- **Instrumented JVM** — a Java agent (`sandbox-runtime`, ASM) rewrites the plugin's dangerous call
  sites to record them, and a `SecurityManager` logs-and-blocks process/socket/file/`exit`/native
  actions the plugin initiates.
- **Mock Paper harness** — minimal Bukkit stubs load the plugin and drive its real
  `onLoad`/`onEnable`/commands/`onDisable`, so its code actually runs.
- **Report integration** — observed behavior becomes *dynamic findings*, each marked **confirms a
  static finding** or **runtime-only** (the alarming case). Dynamic Critical/High evidence floors
  the verdict.

Enable it (requires a reachable Docker daemon and the built agent jar):

```bash
./gradlew :sandbox-runtime:jar      # produces sandbox-runtime/build/libs/sandbox-runtime-*.jar
```

```yaml
# application.yml (or env): all off by default
pluginguard:
  sandbox:
    enabled: true
    runtime-jar-path: "/opt/pluginguard/sandbox-runtime.jar"   # path to the jar above
    image: "eclipse-temurin:21-jre"
    timeout-seconds: 20
    memory-mb: 256
    network: "none"
```

> ⚠️ It runs untrusted code. Run the analyzer where it may talk to Docker (a mounted socket or a
> remote engine), keep `network: none`, and treat the host as exposed to whatever the plugin tries.
> A sandbox only sees the paths it triggers and can be evaded — absence of dynamic findings is **not**
> proof of safety.

## Tests

```bash
cd analyzer && ./gradlew test     # builds and tests both the analyzer and :sandbox-runtime
```

The suite builds synthetic JARs in memory (ASM). Alongside the baseline cases (benign scores
well, an obvious malware sample is Critical, non-JAR caught, native library reported), the
Phase 1 suite (`Phase1DetectorsTest`) asserts one synthetic case per deep-static detector:
recursive nested-jar attribution, `invokedynamic` (custom bootstrap flagged, standard lambda not),
reflection resolution, base64-encoded-class decode-and-rescan, hidden-URL decoding, a class
disguised as an image, the scripting/JNDI/deserialization/`setAccessible`/Robot rules, the
time-bomb heuristic, the remote-code-loader correlation, deeper `plugin.yml`/manifest checks —
plus a false-positive control (a benign plugin with a bundled library raises no Critical combos).

The Phase 3 sandbox is covered without needing Docker: the `:sandbox-runtime` suite drives a
synthetic plugin through the real instrument→harness→capture chain in-process (and tests the
SecurityManager's caller attribution), while `Phase3SandboxTest` asserts the hardened `docker run`
command, behavior-log parsing, dynamic-finding mapping with static correlation, verdict flooring,
and the asynchronous orchestration — all with a stubbed runner and canned behavior.

---

## Roadmap

**Phase 1 — deep static engine (done):** recursive nested-jar analysis, `invokedynamic`,
decode-and-rescan, disguised-payload + entropy detection, a much wider rule table, reflection
resolution and the cross-signal correlation engine. Pure Java, fully covered by tests.

**Phase 2 — supply-chain & reputation (done, opt-in):** CVE lookup for bundled dependencies via
OSV.dev with a TTL disk cache and graceful offline degradation, and SHA-256 reputation lists
(known-malicious / known-good). Both reach the network, so both are **off by default** and enabled
under `pluginguard.supply-chain.*` (`cve-enabled`, `reputation-enabled`, `offline`,
`known-malicious-source`, `known-good-source`, cache dir / TTL / timeouts).

**Phase 3 — dynamic sandbox (done, opt-in):** runs the plugin in an isolated, non-root,
`--network none` Docker container with a mock Paper harness and an instrumented JVM that logs (and
blocks) process/network/file/reflection/`defineClass` actions, then folds the observed behavior into
the report (confirmed vs. runtime-only) and floors the verdict on dynamic Critical/High evidence.
It actually executes the plugin, so it is **off by default** and enabled under
`pluginguard.sandbox.*` (see [Dynamic sandbox](#dynamic-sandbox-phase-3-opt-in)). Honest caveats
about sandbox evasion and dormant code are shown with every dynamic report.

Next: GitHub/SHA provenance + Sigstore signatures · PostgreSQL + a job queue · public report
database · API keys · browser extension / Discord bot / GitHub Action / "Scanned by PluginGuard" badge.
