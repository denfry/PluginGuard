# PluginGuard

**Deep, risk-based static security analysis for Minecraft plugins, mods, resource packs and data packs.**

Upload an artifact and PluginGuard shows what it *really* does before you install it: dangerous
bytecode calls, network indicators, credential-theft markers, known-malware signatures, obfuscation,
bundled dependencies and descriptor validation — distilled into a multi-axis fitness report (security,
performance, …) with an install recommendation and an itemised breakdown by axis.

It auto-detects the artifact kind and analyzes each accordingly:

| Artifact | Input | What's analyzed |
|----------|-------|-----------------|
| **Server plugin** | `.jar` | Bukkit/Spigot/Paper, BungeeCord, Velocity — full bytecode engine + `plugin.yml` |
| **Mod** | `.jar` | Forge/NeoForge (`mods.toml`), Fabric/Quilt (`fabric.mod.json`/`quilt.mod.json`) — same bytecode engine + coremod/transformer & access-widener checks |
| **Resource pack** | `.zip` | `pack.mcmeta`, disguised payloads, phishing text, zip-slip, shaders (assets only — cannot run code) |
| **Data pack** | `.zip` | `.mcfunction` command scanning: auto-run `load`/`tick` tags, `op` commands, lag loops, phishing `tellraw` links |

**Multi-axis fitness report:** Each artifact is scored across independent **security** and **performance**
axes, each yielding a 0–100 score and contributing to an overall **install recommendation** — a signal
combining all axes, except that a Critical security finding acts as an unconditional **security veto**
(install not recommended, regardless of performance score). This multi-axis view separates concerns:
a plugin may have low security risk but high performance risk (e.g. heavy sync I/O in event handlers),
and the system reflects both in a transparent, actionable way.

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
| **Artifact detection** | Auto-classifies the upload (Bukkit/Bungee/Velocity plugin, Forge/NeoForge/Fabric/Quilt mod, resource pack, data pack) so each is judged by the right rules |
| **Structure** | Real JAR vs renamed file, native libs (`.dll/.so/.exe/…`), nested JARs, Java-agent manifests, external manifest `Class-Path`, zip-bomb guards, **zip-slip / path-traversal entries**, **library-namespace squatting** (a class planted inside a trusted third-party package — JetBrains annotations, Commons Lang, Javassist, Gson, Guava, SnakeYAML, org.json — detected generically: a genuine shaded copy always ships its anchor classes, so a namespace present *without* them was planted to hide among the deps) |
| **Nested JARs** | Bundled/shaded `.jar`/`.zip`/`.war` are unpacked and analyzed **recursively** (to a depth limit); findings are attributed with the jar-chain path (`lib.jar!/com/evil/X`) |
| **plugin.yml** | name/version/main/api-version, commands, permissions, missing main class, wildcard perms, backdoor-style commands, `load: STARTUP`/`loadbefore`, remote `libraries:`, dependency count |
| **Bytecode (ASM)** | Process exec, dynamic/remote class loading (incl. `MethodHandles.Lookup.defineClass`, instrumentation, **JNDI lookup**), native loading, reflection + `setAccessible`/`jdk.internal`, **scripting engines** (JS/Groovy/BeanShell/…), **deserialization** (`ObjectInputStream`/XStream), AWT `Robot`/clipboard/desktop, low-level networking (UDP/multicast/RMI), `SecurityManager` removal, **time-bomb** heuristic, `System.exit`/`halt` |
| **invokedynamic** | Bootstrap methods + method-handle arguments are captured; non-standard bootstraps are flagged as obfuscation, and `Foo::dangerous` method references are matched like direct calls |
| **Reflection resolution** | Resolves string operands of `Class.forName("…")` / `getMethod("…")` to apply the dangerous-API rules to reflectively-named targets |
| **Decode & rescan** | Base64/hex (and single-byte XOR) blobs are decoded within strict limits; an embedded class (`CAFEBABE`) is fed back through ASM, embedded archives/native binaries and hidden URLs/shell strings are flagged |
| **Embedded payloads** | Every resource's **raw bytes** are checked against file magic regardless of extension (class/zip/PE/ELF/Mach-O disguised as `.png/.dat/…`), plus an entropy check for encrypted/packed blobs |
| **Strings / IOC** | URLs & Discord/Telegram webhooks, public IPs, shell-command markers, credential-theft paths, base64 blobs |
| **Obfuscation** | Short class/method names, default packages, reflection density, encoded-string density → 0–100 score |
| **Minecraft API** | Platform-specific sinks the generic table misses: console-command dispatch (`Bukkit.dispatchCommand`), operator control (`setOp`), and reading the client session token (`getAccessToken`) |
| **Known malware** | Curated signatures for documented Minecraft malware families: the **fractureiser** worm, a session-stealer RAT, and the CIS-scene cracked-plugin injectors (**HostFlow, Artemka, chbk, PluginMetrics, aph, bStats.jar, ru/bstats**) — injected package namespaces, hard-coded C2 hosts/IPs (e.g. `api-bstats.online`), dropped-file names. A match is strong evidence the file is/was infected |
| **Mods** | Parses `mods.toml`/`neoforge.mods.toml`/`fabric.mod.json`/`quilt.mod.json`; flags coremods / raw class transformers (rewrite arbitrary classes at load), `IMixinConfigPlugin`, and access-wideners |
| **Resource / data packs** | `pack.mcmeta` validity; data-pack `.mcfunction` scanning for auto-run `load`/`tick` tags, `op`/`deop` commands, self-recursive lag loops, and `tellraw` phishing links; shader notice |
| **Correlation (combo)** | Raises Critical/High when capabilities combine: network + class loading = remote loader; class loading + crypto/encoded = encrypted payload loader; reflection + process; deserialization + network; native + process = dropper; scripting + network; credential paths + exfiltration = stealer; **op/console control + concealment = operator backdoor** |
| **Dependencies** | Best-effort SBOM from `pom.properties` + nested JARs |
| **CVE check** *(opt-in)* | Queries OSV.dev for known vulnerabilities in bundled `groupId:artifactId:version` dependencies; severity from CVSS/GHSA, links to the advisory; disk cache + offline fallback |
| **Reputation** *(opt-in)* | Matches the JAR's (and nested JARs') SHA-256 against pull-able known-malicious (Critical) / known-good (info) lists |
| **Performance (lag risk)** | Static prediction of TPS impact: blocking I/O (JDBC/HTTP/file), `Thread.sleep`, sync chunk loads and other heavy work reachable from hot paths (event handlers, repeating sync tasks) — scored as its own axis, never mixed into the security score |
| **Dynamic sandbox** *(opt-in)* | **Executes** the plugin in a hardened, non-root, `--network none` Docker container with an instrumented JVM + mock Paper harness; records real process/socket/file/reflection/`defineClass` behavior, cross-checks it against the static findings (confirmed vs. *runtime-only*), and floors the verdict on dynamic Critical/High evidence |

> 🧪 **Honest residual risk.** Deciding whether an arbitrary program is malicious is undecidable
> (Rice's theorem). Static analysis can be defeated by genuinely dynamic code (targets built only
> at runtime), strong encryption of payloads, and logic gated on the environment. The dynamic
> sandbox narrows that gap but has its own blind spots: it only sees code paths it triggers, and
> malware can detect the sandbox and lie low (sandbox evasion). PluginGuard's goal is to make
> hiding a backdoor *expensive and noisy*, not to prove safety. The report always states **risk**,
> never a "safe" verdict.
>
> The dynamic sandbox (below) runs **server plugins only** — mods, resource packs and data packs
> receive deep *static* analysis but are never executed, and resource packs are inherently low-risk
> (assets, no code). A clean static scan of a mod is therefore not a guarantee.
>
> **Performance analysis caveat:** Static analysis predicts *risk of lag*, not measured TPS or real-world
> impact. It cannot see actual load patterns, data sizes, async/non-blocking library use, or JVM optimizations.
> Deep call-graph findings (e.g. "blocking I/O reachable from tick loop") carry lower confidence than
> direct bytecode rule matches and should be weighed against the plugin's known behavior and load profile.

---

## Architecture

```
web/        Next.js 16 + Tailwind v4 — dark security dashboard (upload, report, demo)
analyzer/   Spring Boot 3.5 (Java 21) — REST API + the static-analysis engine (ASM, SnakeYAML)
analyzer/sandbox-runtime/   Plain Java + ASM — the JVM agent + mock Bukkit harness that runs
                            INSIDE the isolated container (kept out of the analyzer's own classpath)
sample-plugins/   Synthetic benign & malicious-looking plugins for demo and tests
```

The browser uploads a `.jar` to the analyzer's `POST /api/scan`, which runs the static pipeline
synchronously (it is fast) and returns a JSON report. The web app renders it and caches it by id; a
direct visit re-fetches `GET /api/scan/{id}`. When the dynamic sandbox is enabled, the static report
comes back immediately with a `sandbox` section in `PENDING`/`RUNNING`, and the page polls
`GET /api/scan/{id}` until the asynchronous run reaches `COMPLETED`.

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
| `POST` | `/api/scan` | multipart `file` (`.jar` plugin/mod, or `.zip`/`.mcpack`/`.litemod` pack) → full `ScanResult` JSON |
| `GET`  | `/api/scan/{id}` | a previously generated report (in-memory, ephemeral) |
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

**Phase 4 — multi-artifact coverage (done):** auto-detects the artifact kind and extends the engine
beyond Bukkit plugins to Forge/NeoForge/Fabric/Quilt **mods** (descriptor parsing + coremod/transformer
& access-widener checks; the whole bytecode engine applies since a mod is just a JAR of classes),
**resource packs** (pack.mcmeta, disguised payloads, phishing, zip-slip, shaders) and **data packs**
(`.mcfunction` scanning: auto-run tags, `op` commands, lag loops, phishing links). It also closes the
biggest plugin gaps — Minecraft-specific sinks (console-command dispatch, `setOp`, session-token read),
a known-malware signature table (**fractureiser** and a session-stealer RAT), broader credential IOCs,
and an operator-backdoor correlation. Mods/packs are static-only (the sandbox runs plugins).

Next: GitHub/SHA provenance + Sigstore signatures · PostgreSQL + a job queue · public report
database · API keys · browser extension / Discord bot / GitHub Action / "Scanned by PluginGuard" badge.
