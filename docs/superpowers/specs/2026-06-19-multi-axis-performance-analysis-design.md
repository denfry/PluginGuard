# Design — Multi-Axis Fitness Report + Performance (Lag-Risk) Analyzer

- **Date:** 2026-06-19
- **Status:** Approved (brainstorming)
- **Sub-project:** 1 of 5 in the "broader-than-security" expansion
- **Engine version target:** `0.2.0`

---

## 1. Goal

Turn PluginGuard's report from *"is this safe?"* into *"should I install this on my server?"* by
generalizing the single security score into a **multi-axis fitness report**, and shipping the first
new axis — **Performance (lag-risk)** — which statically predicts whether an artifact will hurt
server TPS. No competing platform (Modrinth, CurseForge, Hangar) offers static lag-risk analysis.

### Non-goals (later sub-projects, separate specs)

- Compatibility / conflict analysis (loader + MC version + API-existence + Folia-safety).
- Code-health / quality analysis.
- License / legality analysis.

These three are deliberately **out of scope** here. The `Axis` enum reserves their names so they
slot in without a second foundation refactor, but no analyzer fills them in this sub-project.

---

## 2. Background — current single-axis model

- `ScanResult` carries one `int score` (0–100, higher = safer) and one `Verdict`.
- Every `Finding` has a `Category`; `ScoreCalculator.score(List<Finding>)` folds all findings into
  the single score (start at 100, deduct per `ruleId`, bounded repeat surcharge, COMBO multiplier,
  CRITICAL/HIGH score ceilings).
- Analyzers implement `Analyzer` and mutate an `AnalysisContext`; the engine runs them in `@Order`,
  then scores. Each class is ASM-scanned once into a `ClassScan` (methods, **invocations**, string
  constants, taint flows). `Invocation` already records `callerClass` + `callerMethod` + callee
  `owner/name/descriptor` — the raw material for an intra-jar call graph.
- The web mirrors the JSON contract in `web/lib/types.ts` and renders a single `ScoreGauge`.

The current `score`/`verdict` is, in effect, the **Security** axis.

---

## 3. Concept — multi-axis fitness report

The report exposes several independent axes, each with its own sub-score and verdict, plus one
combined recommendation:

```
🛡  Security        82/100   (existing behavior, unchanged)
⚡  Performance     41/100   (NEW — lag risk)
🧩  Compatibility   —        (reserved; later spec)
🩺  Code health     —        (reserved; later spec)
⚖  Legal/License   —        (reserved; later spec)
─────────────────────────────
Recommendation: INSTALL_WITH_CARE — "Security clean, but high lag risk:
opens a DB connection on the server thread on every PlayerMoveEvent."
```

**Security keeps veto power**: excellent performance never redeems a backdoor; a malware verdict
always dominates the overall recommendation.

---

## 4. Foundation design (multi-axis model)

All changes are additive and backward-compatible. `score`/`verdict` remain and equal the SECURITY
axis, so existing clients and the existing UI keep working.

### 4.1 New / changed model types (`engine/model`)

- **`Axis`** (new enum): `SECURITY, PERFORMANCE, COMPATIBILITY, HEALTH, LICENSE`. All five declared;
  only SECURITY + PERFORMANCE are populated in this sub-project.
- **`Category`** — each constant declares its `Axis` (constructor field + `axis()` accessor). Every
  existing category maps to `SECURITY` (no behavior change). Add `PERFORMANCE` → `Axis.PERFORMANCE`.
- **`AxisScore`** (new record): `(Axis axis, int score, Verdict verdict, SeverityCounts counts,
  String headline)`. `headline` is a short plain-language summary of the axis.
- **`Recommendation`** (new record): `(RecommendationLevel level, String headline,
  List<String> perAxis)` where `RecommendationLevel` (new enum) is
  `SAFE_TO_INSTALL, INSTALL_WITH_CARE, RISKY, AVOID, DO_NOT_INSTALL`.
- **`ScanResult`** gains `List<AxisScore> axes` and `Recommendation recommendation`. Existing fields
  stay. `withSandbox(...)` updated to carry the new fields through.

### 4.2 Scoring (`scoring`)

- **`ScoreCalculator`** refactor: the current deduction algorithm is already axis-agnostic — it only
  consumes findings. Extract `scoreAxis(Axis axis, List<Finding> axisFindings)` (same algorithm),
  and add a top-level method that buckets findings by `category.axis()`, scores each axis, and
  returns `List<AxisScore>`. The SECURITY axis is computed exactly as today → existing scoring tests
  stay green. An axis with no findings is **omitted** from the report (not shown as 100/blank).
- **`RecommendationCalculator`** (new `@Component`) maps axis verdicts → `Recommendation`:
  - SECURITY `CRITICAL_RISK` → `DO_NOT_INSTALL`.
  - SECURITY `HIGH_RISK` → `AVOID`.
  - else worst non-security axis: any `CRITICAL_RISK` → `AVOID`; any `HIGH_RISK` → `RISKY`;
    any `MEDIUM_RISK` → `INSTALL_WITH_CARE`; otherwise `SAFE_TO_INSTALL`.
  - `headline` names the dominant axis + reason; `perAxis` is one line per populated axis.
  - It is a **recommendation, not a guarantee** — the per-axis breakdown is always shown.

### 4.3 Engine wiring (`AnalysisEngine`)

After running analyzers and sorting findings: bucket by axis, call `ScoreCalculator` per axis to get
`axes`, keep `score`/`verdict` = SECURITY axis, call `RecommendationCalculator`, and assemble the
extended `ScanResult`. Bump `ENGINE_VERSION` to `0.2.0`.

---

## 5. Performance analyzer design (`PerformanceAnalyzer`, Hybrid C)

A new `Analyzer` ordered after `BytecodeAnalyzer` (needs `ClassScan` invocations). Five components.

### 5.1 Method-annotation capture (engine extension)

`ClassScanner`'s `MethodVisitor` is extended to record method annotation descriptors (`visitAnnotation`).
`MethodInfo` gains `List<String> annotations`. Required to distinguish event handlers / subscribers
from ordinary methods. Small, isolated, also useful to later (health/compat) analyzers.

### 5.2 Pluggable hot-path models

Interface `HotPathModel` → produces hot **entrypoints**: `(class, methodName)` each with a base
*heat* (`HOT` / `WARM` / `COOL`). Implementation(s) selected by `ctx.artifactType()`:

- **`BukkitHotPathModel`** (PLUGIN_BUKKIT): a method is an entrypoint when its class implements
  `org.bukkit.event.Listener`, the method is annotated `@org.bukkit.event.EventHandler`, and its
  single parameter type ends in `Event`. Heat from an event table — `PlayerMoveEvent`,
  `EntityMoveEvent`, `VehicleMoveEvent`, `BlockPhysicsEvent`, `ProjectileHitEvent`,
  `EntityDamageEvent`, `FoodLevelChangeEvent`, `PlayerInteractEvent` = `HOT`; `AsyncPlayerChatEvent`
  = `WARM`; most one-shot events (`PlayerJoinEvent`, `PlayerQuitEvent`) = `COOL`. Plus `run()` of
  classes extending `BukkitRunnable` / implementing `Runnable` that are registered via a **sync**
  scheduler (`runTaskTimer`, `scheduleSyncRepeatingTask`, `runTask`). Registration via an **async**
  scheduler (`...Asynchronously`, `runTaskAsynchronously`) is **not** hot — blocking I/O there is
  legitimate. This sync/async distinction is the main false-positive control.
- **`ForgeHotPathModel`** (MOD_FORGE / MOD_NEOFORGE): methods annotated `@SubscribeEvent` whose
  parameter is a tick event (`TickEvent`, `LevelTickEvent`, `ServerTickEvent`).
- **`FabricHotPathModel`** (MOD_FABRIC / MOD_QUILT): callbacks/lambdas registered to
  `ServerTickEvents` / `ClientTickEvents` / world-tick callbacks.
- **`ProxyHotPathModel`** (PLUGIN_BUNGEE / PLUGIN_VELOCITY): per-connection handlers
  (Bungee `@EventHandler`, Velocity `@Subscribe`). Proxies have no tick; heat is "per connection".
- **`DataPackHotPathModel`** (DATA_PACK): no bytecode. Implemented as **re-routing**: existing
  `PackAnalyzer` lag-loop / auto-run findings are emitted under (or duplicated to) `Category.PERFORMANCE`
  so they feed the Performance axis. (PackAnalyzer keeps its security-relevant findings too.)

If no model matches the artifact type (e.g. RESOURCE_PACK), the analyzer is a no-op.

### 5.3 Call-graph reachability (the "C" in Hybrid C)

- Build an intra-jar call graph from captured `Invocation`s: node = `(classInternalName, methodName)`,
  edge = caller → callee for any callee whose `owner` resolves to a class inside the jar.
  *Note:* `Invocation.callerMethod` is a name without descriptor, so overloads collapse — acceptable
  imprecision, recorded as a caveat.
- From each hot entrypoint, BFS to depth `D` (default 5), assigning each reached method
  `(heat, distance)` (keep the **max heat / min distance** when reached by several paths). Visited-set
  guards recursion/cycles.
- **Cold-path suppression**: a sink in method `m` is only reported if `m` is reachable from ≥1 hot
  entrypoint. Methods reachable only from cold entrypoints (`onEnable`, `onDisable`, command
  executors) never produce performance findings.
- Virtual dispatch is resolved best-effort (match callee name on the owner and its in-jar subtypes);
  unresolved/library callees are sink-check targets, not graph edges.

### 5.4 Performance sink table

Each sink: `intrinsicWeight` (`LIGHT` / `MODERATE` / `HEAVY` / `SEVERE`) + `alwaysBadOnMainThread`
(a floor even at `COOL` heat). Initial table:

- **Blocking main-thread I/O (SEVERE):** JDBC (`java.sql.DriverManager.getConnection`,
  `java.sql.Statement.execute*`/`executeQuery`/`executeUpdate`), synchronous HTTP
  (`java.net.HttpURLConnection.getInputStream/connect`, `java.net.http.HttpClient.send`),
  `java.net.Socket` connect/read, `java.nio.file.Files.*` / `FileInputStream`/`FileOutputStream`.
- **Blocking waits (HEAVY, alwaysBad):** `Thread.sleep`, `Object.wait`, `Future.get` (no timeout),
  `CompletableFuture.join`/`get`.
- **Synchronous world/chunk ops (HEAVY, alwaysBad):** `World.getChunkAt`/`loadChunk`/`getBlockAt`
  (forces gen), `World.getEntities`/`getNearbyEntities` (per-tick), iterating
  `Bukkit.getOnlinePlayers()` inside a hot path.
- **Hot-path anti-patterns (MODERATE):** `java.util.regex.Pattern.compile` inside a hot method
  (should be a static field), reflective calls per tick, `Logger.info`/`System.out.println` per tick.
- **Allocation in loops (LIGHT):** heavy `new` inside a hot loop (best-effort).

The table is data, not code branches, so adding sinks later is a one-line entry.

### 5.5 Severity formula & findings

`severity = combine(intrinsicWeight, heat, distanceDecay)`, realized as a small lookup matrix
producing `CRITICAL` / `HIGH` / `MEDIUM` / `LOW`, with `alwaysBadOnMainThread` sinks getting a floor
of `MEDIUM` even at `COOL`. `scoreImpact` derives from severity (consistent with existing findings).

Each finding: `category = PERFORMANCE`, `location = class#method`, `evidence = the sink call`,
plain-admin `description` (e.g. *"Opens a database connection on the server thread every time a
player moves — this will freeze the server under load"*) and `recommendation` (e.g. *"Move the query
to an async task (`runTaskAsynchronously`) and cache the result"*). The reachability distance /
confidence is stated in the description (*"called directly from PlayerMoveEvent"* vs *"reachable 3
calls deep from a repeating task"*).

---

## 6. Web / UI design (`web/`)

> **Constraint:** `web/AGENTS.md` warns this is a non-standard Next.js with breaking changes — read
> the relevant guide under `node_modules/next/dist/docs/` before writing web code. `ScoreGauge.tsx`
> has uncommitted WIP — read and preserve it; parameterize rather than clobber.

- **`web/lib/types.ts`**: add `Axis`, `AxisScore`, `Recommendation`, `RecommendationLevel`, the
  `PERFORMANCE` category, and `axes: AxisScore[]` + `recommendation: Recommendation` on `ScanResult`
  (keep `score`/`verdict`).
- **`ScoreGauge.tsx`**: parameterize (axis label + color + score) instead of the hard-coded
  `"safety / 100"`, preserving the existing WIP and hydration-safe rendering.
- **`AxisScores.tsx`** (new): a horizontal strip of compact axis meters (icon + axis name +
  score/verdict), styled in the existing forensic-instrument theme.
- **`ReportView.tsx`**: render the overall `recommendation` banner on top, then the axis strip, then
  findings (PERFORMANCE gets an icon + section like other categories via `icons.tsx`/`format.ts`).
- **`DemoData`** (analyzer) + any web demo fixture: include `axes` + `recommendation` so the demo and
  `/api/demo` render the new sections.

---

## 7. Testing strategy

Mirror the existing style — synthetic JARs built in-memory with `JarBuilder` (ASM), one case per
rule, plus false-positive controls.

- **Foundation:** multi-axis scoring; SECURITY axis byte-for-byte equal to old behavior (regression);
  axis independence (a perf finding doesn't move the security score and vice versa);
  `RecommendationCalculator` mapping (security veto beats good perf; perf-CRITICAL with clean security
  → `AVOID`; all-clean → `SAFE_TO_INSTALL`).
- **Hot-path models:** Bukkit listener detection (Listener + `@EventHandler` + `*Event` param);
  sync-vs-async scheduler distinction; Forge/Fabric/proxy entrypoint detection.
- **Reachability:** sink directly in handler → high confidence; sink via a helper 1–N deep → reported
  with lower confidence; sink reachable only from `onEnable`/command → **suppressed** (no finding);
  recursive call graph terminates.
- **Sink table:** each sink rule fires on a synthetic case; JDBC in `PlayerMoveEvent` → CRITICAL perf;
  the same JDBC wrapped in `runTaskAsynchronously` → **not** flagged (false-positive control); a
  benign plugin → high performance score.
- **Data pack:** existing lag-loop / auto-run finding now also feeds the PERFORMANCE axis.
- **Web:** `types.ts` compiles; `npm run build` / lint pass; demo renders axes + recommendation.

**Done when:** `./gradlew test` is green (including unchanged security regressions), each new
detector has a synthetic case that fires with the expected `ruleId`, benign artifacts get no false
CRITICAL performance findings, and the web builds and renders the new sections.

---

## 8. Honest framing (project ethos)

Static performance analysis predicts **risk of lag**, not measured TPS. It cannot see real server
load, data-set sizes, or whether an async wrapper exists at runtime; virtual-dispatch resolution is
best-effort, so deep findings carry lower confidence. Like the rest of PluginGuard, the report states
**risk**, never a guarantee. README and PLAN get a new "Phase 5 — multi-axis fitness" section noting
this.

---

## 9. Decisions on record (from brainstorming)

1. Primary direction: **broader than security** (multi-axis), not deeper security.
2. Full vision is four new axes; build order: **foundation + Performance first**, then Compatibility,
   Health, License (each its own spec).
3. Performance scope this sub-project: **plugins + mods + proxies + data packs** (max coverage) via
   pluggable hot-path models.
4. Reachability strategy: **Hybrid C** (call graph + confidence-by-distance + cold-path suppression,
   degrading to direct-context).
5. Include the combined **overall recommendation** (security veto) in this sub-project.

---

## 10. High-level change list

**Analyzer (new):** `engine/model/Axis.java`, `engine/model/AxisScore.java`,
`engine/model/Recommendation.java` (+ `RecommendationLevel`),
`engine/analyzers/PerformanceAnalyzer.java`, `engine/perf/HotPathModel.java` (+ Bukkit/Forge/Fabric/
Proxy/DataPack implementations), `engine/perf/CallGraph.java`, `engine/perf/PerfSinkTable.java`,
`scoring/RecommendationCalculator.java`.

**Analyzer (changed):** `engine/model/Category.java` (axis per constant + `PERFORMANCE`),
`engine/model/ScanResult.java` (+`axes`, +`recommendation`), `scoring/ScoreCalculator.java`
(per-axis), `engine/AnalysisEngine.java` (assemble axes + recommendation, bump version),
`engine/bytecode/ClassScanner.java` + `MethodInfo.java` (annotation capture),
`engine/analyzers/PackAnalyzer.java` (re-route lag findings to PERFORMANCE), `api/DemoData.java`.

**Web (changed):** `lib/types.ts`, `components/ScoreGauge.tsx`, `components/ReportView.tsx`,
`components/icons.tsx`, `lib/format.ts`; **new** `components/AxisScores.tsx`.

**Docs:** `README.md`, `PLAN.md` (Phase 5 section).

**Tests:** new suites for foundation scoring/recommendation, hot-path models, reachability, perf
sinks; regression assertions that the security axis is unchanged.
