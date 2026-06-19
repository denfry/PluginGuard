# Multi-Axis Fitness Report + Performance (Lag-Risk) Analyzer — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Generalize PluginGuard's single security score into a multi-axis fitness report and ship the first new axis — static Performance (lag-risk) analysis — plus a combined "should I install this?" recommendation with security veto.

**Architecture:** Additive, backward-compatible. A new `Axis` dimension is attached to every `Category`; `ScoreCalculator` scores each axis independently; a new `PerformanceAnalyzer` reuses the existing ASM `ClassScan`/`Invocation` data to find perf-sensitive calls reachable from "hot paths" (event handlers, repeating sync tasks) via an intra-jar call graph (Hybrid C). The top-level `score`/`verdict` stay and equal the SECURITY axis, so existing clients keep working.

**Tech Stack:** Java 21, Spring Boot 3.5, ASM (tree API), JUnit 5 + AssertJ (`@SpringBootTest`), Next.js (non-standard fork) + Tailwind v4 for the web.

## Global Constraints

- **Java 21**, Spring Boot 3.5; analyzer build/test via `cd analyzer && ./gradlew test`.
- **No new runtime dependencies.** Reuse ASM (already present) and existing utilities.
- **Never load or execute** any class from the analyzed JAR; ASM read-only parsing only. Analyzers must be stateless and side-effect-free beyond mutating `AnalysisContext`.
- **Backward-compatible JSON contract:** `ScanResult.score`/`verdict` remain and equal the SECURITY axis. New fields are additive.
- **`ENGINE_VERSION` becomes `0.2.0`** (in `AnalysisEngine`).
- **Web is a non-standard Next.js fork** (`web/AGENTS.md`): read the relevant guide under `web/node_modules/next/dist/docs/` before writing web code. **Do not clobber** the uncommitted WIP in `web/components/ScoreGauge.tsx`, `web/app/page.tsx`, `web/app/globals.css`, `web/app/layout.tsx`, `web/components/FeatureGrid.tsx` — parameterize/extend, re-read before editing.
- **Tests** mirror existing style: synthetic JARs from `dev.pluginguard.support.JarBuilder` (ASM), `@SpringBootTest` with `@Autowired AnalysisEngine engine`, AssertJ assertions, one synthetic case per rule + a false-positive control.
- **Commit after each task** (after its tests pass). Work on branch `feat/multi-axis-performance-analysis`.

---

## File Structure

**New (analyzer main):**
- `engine/model/Axis.java` — the five analysis axes.
- `engine/model/AxisScore.java` — per-axis score record.
- `engine/model/RecommendationLevel.java` — install-recommendation enum.
- `engine/model/Recommendation.java` — combined recommendation record.
- `scoring/RecommendationCalculator.java` — maps axis verdicts → recommendation (security veto).
- `engine/perf/Heat.java` — hot-path heat level enum.
- `engine/perf/HotEntrypoint.java` — a (class, method, heat) entrypoint record.
- `engine/perf/HotPathModel.java` — interface: artifact-family hot-path detection.
- `engine/perf/BukkitHotPathModel.java`, `ForgeHotPathModel.java`, `FabricHotPathModel.java`, `ProxyHotPathModel.java` — implementations.
- `engine/perf/PerfSinkTable.java` — perf-sensitive sinks + weights.
- `engine/perf/CallGraph.java` — intra-jar call graph + reachability.
- `engine/analyzers/PerformanceAnalyzer.java` — the `Analyzer`.

**Changed (analyzer main):**
- `engine/model/Category.java` — add `axis()` + `PERFORMANCE`.
- `engine/bytecode/MethodInfo.java` — add `annotations`.
- `engine/bytecode/ClassScanner.java` — capture method annotations.
- `scoring/ScoreCalculator.java` — add `scoreByAxis(...)`.
- `engine/model/ScanResult.java` — add `axes`, `recommendation`.
- `engine/AnalysisEngine.java` — assemble axes + recommendation; bump version.
- `api/DemoData.java` — supply `axes` + `recommendation` (+ a demo perf finding).

**Changed (analyzer test):** `support/JarBuilder.java` (perf scaffolding); new test classes.

**Changed (web):** `lib/types.ts`, `lib/format.ts`, `components/icons.tsx`, `components/ScoreGauge.tsx`, `components/ReportView.tsx`; new `components/AxisScores.tsx`.

**Changed (docs):** `README.md`, `PLAN.md`.

---

## Task 1: `Axis` enum + `Category.axis()` mapping

**Files:**
- Create: `analyzer/src/main/java/dev/pluginguard/engine/model/Axis.java`
- Modify: `analyzer/src/main/java/dev/pluginguard/engine/model/Category.java`
- Test: `analyzer/src/test/java/dev/pluginguard/engine/model/CategoryAxisTest.java`

**Interfaces:**
- Produces: `enum Axis { SECURITY, PERFORMANCE, COMPATIBILITY, HEALTH, LICENSE }` with `String displayName()`; `Category.axis()` returning an `Axis`; new constant `Category.PERFORMANCE`.

- [ ] **Step 1: Write the failing test**

```java
// analyzer/src/test/java/dev/pluginguard/engine/model/CategoryAxisTest.java
package dev.pluginguard.engine.model;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

class CategoryAxisTest {

    @Test
    void everyCategoryHasAnAxis() {
        for (Category c : Category.values()) {
            assertThat(c.axis()).as("axis for " + c).isNotNull();
        }
    }

    @Test
    void existingSecurityCategoriesMapToSecurity() {
        assertThat(Category.NETWORK.axis()).isEqualTo(Axis.SECURITY);
        assertThat(Category.OBFUSCATION.axis()).isEqualTo(Axis.SECURITY);
        assertThat(Category.DATA_PACK.axis()).isEqualTo(Axis.SECURITY);
    }

    @Test
    void performanceCategoryMapsToPerformanceAxis() {
        assertThat(Category.PERFORMANCE.axis()).isEqualTo(Axis.PERFORMANCE);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd analyzer && ./gradlew test --tests "dev.pluginguard.engine.model.CategoryAxisTest"`
Expected: COMPILE FAILURE — `Axis` and `Category.PERFORMANCE`/`axis()` do not exist.

- [ ] **Step 3: Create `Axis`**

```java
// analyzer/src/main/java/dev/pluginguard/engine/model/Axis.java
package dev.pluginguard.engine.model;

/**
 * A top-level dimension the report scores independently. SECURITY is the original score; the others
 * are answered by their own analyzers. Only SECURITY and PERFORMANCE are populated today.
 */
public enum Axis {
    SECURITY("Security"),
    PERFORMANCE("Performance"),
    COMPATIBILITY("Compatibility"),
    HEALTH("Code health"),
    LICENSE("Legal / license");

    private final String displayName;

    Axis(String displayName) {
        this.displayName = displayName;
    }

    public String displayName() {
        return displayName;
    }
}
```

- [ ] **Step 4: Add the axis to every `Category` constant**

Replace the whole enum body of `Category.java` with constants that declare their axis, add `PERFORMANCE`, and add the accessor. Keep the existing Javadoc on the type.

```java
public enum Category {
    STRUCTURE(Axis.SECURITY),
    PLUGIN_YML(Axis.SECURITY),
    NETWORK(Axis.SECURITY),
    PROCESS(Axis.SECURITY),
    CLASS_LOADING(Axis.SECURITY),
    NATIVE(Axis.SECURITY),
    FILESYSTEM(Axis.SECURITY),
    CRYPTO(Axis.SECURITY),
    REFLECTION(Axis.SECURITY),
    SCRIPTING(Axis.SECURITY),
    DESERIALIZATION(Axis.SECURITY),
    SYSTEM(Axis.SECURITY),
    OBFUSCATION(Axis.SECURITY),
    STRING_IOC(Axis.SECURITY),
    SUPPLY_CHAIN(Axis.SECURITY),
    COMBO(Axis.SECURITY),
    MINECRAFT(Axis.SECURITY),
    MALWARE_SIGNATURE(Axis.SECURITY),
    RESOURCE_PACK(Axis.SECURITY),
    DATA_PACK(Axis.SECURITY),
    PROVENANCE(Axis.SECURITY),
    /** Performance / lag-risk findings (heavy work on the server thread, blocking I/O in hot paths). */
    PERFORMANCE(Axis.PERFORMANCE);

    private final Axis axis;

    Category(Axis axis) {
        this.axis = axis;
    }

    /** The report axis this category contributes to. */
    public Axis axis() {
        return axis;
    }
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd analyzer && ./gradlew test --tests "dev.pluginguard.engine.model.CategoryAxisTest"`
Expected: PASS (3 tests).

- [ ] **Step 6: Commit**

```bash
git add analyzer/src/main/java/dev/pluginguard/engine/model/Axis.java \
        analyzer/src/main/java/dev/pluginguard/engine/model/Category.java \
        analyzer/src/test/java/dev/pluginguard/engine/model/CategoryAxisTest.java
git commit -m "feat(model): add Axis dimension and Category->Axis mapping"
```

---

## Task 2: `AxisScore` + per-axis scoring

**Files:**
- Create: `analyzer/src/main/java/dev/pluginguard/engine/model/AxisScore.java`
- Modify: `analyzer/src/main/java/dev/pluginguard/scoring/ScoreCalculator.java`
- Test: `analyzer/src/test/java/dev/pluginguard/scoring/ScoreByAxisTest.java`

**Interfaces:**
- Consumes: `Axis`, `Category.axis()`, `Finding`, `Verdict.from`, `SeverityCounts.from`.
- Produces: `record AxisScore(Axis axis, int score, Verdict verdict, SeverityCounts counts, String headline)`; `List<AxisScore> ScoreCalculator.scoreByAxis(List<Finding> findings)` — one entry per axis that has ≥1 finding, sorted by `Axis.ordinal()`. The existing `int score(List<Finding>)` is unchanged.

- [ ] **Step 1: Write the failing test**

```java
// analyzer/src/test/java/dev/pluginguard/scoring/ScoreByAxisTest.java
package dev.pluginguard.scoring;

import dev.pluginguard.engine.model.Axis;
import dev.pluginguard.engine.model.AxisScore;
import dev.pluginguard.engine.model.Category;
import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.Severity;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ScoreByAxisTest {

    private final ScoreCalculator calc = new ScoreCalculator();

    private static Finding f(Category cat, Severity sev, String ruleId, int impact) {
        return Finding.builder(ruleId, cat, sev).title(ruleId).scoreImpact(impact).build();
    }

    @Test
    void securityAxisScoreEqualsLegacyScoreWhenOnlySecurityFindings() {
        List<Finding> findings = List.of(
                f(Category.NETWORK, Severity.LOW, "A", 8),
                f(Category.REFLECTION, Severity.MEDIUM, "B", 6));

        int legacy = calc.score(findings);
        List<AxisScore> axes = calc.scoreByAxis(findings);

        AxisScore security = axes.stream().filter(a -> a.axis() == Axis.SECURITY).findFirst().orElseThrow();
        assertThat(security.score()).isEqualTo(legacy);
        assertThat(axes).extracting(AxisScore::axis).containsExactly(Axis.SECURITY); // no perf findings
    }

    @Test
    void axesAreScoredIndependently() {
        List<Finding> findings = List.of(
                f(Category.NETWORK, Severity.LOW, "SEC", 5),
                f(Category.PERFORMANCE, Severity.CRITICAL, "PERF", 35));

        List<AxisScore> axes = calc.scoreByAxis(findings);

        AxisScore security = axes.stream().filter(a -> a.axis() == Axis.SECURITY).findFirst().orElseThrow();
        AxisScore perf = axes.stream().filter(a -> a.axis() == Axis.PERFORMANCE).findFirst().orElseThrow();
        // The perf-critical does NOT drag the security score down.
        assertThat(security.score()).isEqualTo(95);
        assertThat(perf.score()).isLessThanOrEqualTo(15);
        assertThat(perf.verdict().name()).isEqualTo("CRITICAL_RISK");
    }

    @Test
    void axisWithNoFindingsIsOmitted() {
        List<AxisScore> axes = calc.scoreByAxis(List.of(f(Category.NETWORK, Severity.LOW, "A", 5)));
        assertThat(axes).extracting(AxisScore::axis).containsExactly(Axis.SECURITY);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd analyzer && ./gradlew test --tests "dev.pluginguard.scoring.ScoreByAxisTest"`
Expected: COMPILE FAILURE — `AxisScore` and `scoreByAxis` do not exist.

- [ ] **Step 3: Create `AxisScore`**

```java
// analyzer/src/main/java/dev/pluginguard/engine/model/AxisScore.java
package dev.pluginguard.engine.model;

/**
 * The score for one {@link Axis}, computed from only that axis's findings.
 *
 * @param axis     the analysis dimension
 * @param score    0–100 (higher is better) for this axis alone
 * @param verdict  risk band for this axis
 * @param counts   finding counts (this axis only)
 * @param headline one-line plain-language summary
 */
public record AxisScore(Axis axis, int score, Verdict verdict, SeverityCounts counts, String headline) {
}
```

- [ ] **Step 4: Add `scoreByAxis` to `ScoreCalculator`**

Refactor: extract the existing deduction loop into a private `deduct(List<Finding>)` returning the raw 0–100 score (without the severity-ceiling step), then have both `score(...)` and the per-axis path apply the ceilings. Add the imports `dev.pluginguard.engine.model.Axis`, `AxisScore`, `SeverityCounts`, `Verdict`, `java.util.ArrayList`.

Replace the body of `score(List<Finding>)` and add the new methods:

```java
public int score(List<Finding> findings) {
    return applyCeilings(deduct(findings), findings);
}

/** One {@link AxisScore} per axis that has at least one finding, ordered by {@link Axis} ordinal. */
public List<AxisScore> scoreByAxis(List<Finding> findings) {
    List<AxisScore> out = new ArrayList<>();
    for (Axis axis : Axis.values()) {
        List<Finding> axisFindings = findings.stream()
                .filter(f -> f.category().axis() == axis)
                .toList();
        if (axisFindings.isEmpty()) {
            continue;
        }
        int score = applyCeilings(deduct(axisFindings), axisFindings);
        SeverityCounts counts = SeverityCounts.from(axisFindings);
        Verdict verdict = Verdict.from(score, counts);
        out.add(new AxisScore(axis, score, verdict, counts, headline(axis, counts)));
    }
    return out;
}

/** Raw 0–100 score from the per-rule deduction model, before severity ceilings. */
private double rawDeduction(List<Finding> findings) {
    Map<String, List<Finding>> byRule = findings.stream()
            .collect(Collectors.groupingBy(Finding::ruleId));
    double deduction = 0;
    for (List<Finding> group : byRule.values()) {
        int impact = group.stream().mapToInt(Finding::scoreImpact).max().orElse(0);
        if (impact == 0) {
            continue;
        }
        int extraOccurrences = Math.min(group.size() - 1, MAX_EXTRA_OCCURRENCES);
        double base = impact + extraOccurrences * impact * EXTRA_OCCURRENCE_WEIGHT;
        if (group.get(0).category() == Category.COMBO) {
            base *= COMBO_MULTIPLIER;
        }
        deduction += base;
    }
    return deduction;
}

private int deduct(List<Finding> findings) {
    int score = (int) Math.round(100 - rawDeduction(findings));
    return Math.max(0, Math.min(100, score));
}

private int applyCeilings(int score, List<Finding> findings) {
    boolean hasCritical = findings.stream().anyMatch(f -> f.severity() == Severity.CRITICAL);
    boolean hasHigh = findings.stream().anyMatch(f -> f.severity() == Severity.HIGH);
    if (hasCritical) {
        return Math.min(score, CRITICAL_SCORE_CEILING);
    } else if (hasHigh) {
        return Math.min(score, HIGH_SCORE_CEILING);
    }
    return score;
}

private static String headline(Axis axis, SeverityCounts counts) {
    int serious = counts.critical() + counts.high();
    if (serious > 0) {
        return serious + " serious " + axis.displayName().toLowerCase() + " issue(s)";
    }
    if (counts.total() > 0) {
        return counts.total() + " minor " + axis.displayName().toLowerCase() + " note(s)";
    }
    return "No " + axis.displayName().toLowerCase() + " issues found";
}
```

Add the import `import dev.pluginguard.engine.model.Axis;` and `import dev.pluginguard.engine.model.AxisScore;` and `import dev.pluginguard.engine.model.SeverityCounts;` and `import dev.pluginguard.engine.model.Verdict;` and `import java.util.ArrayList;` to the top of `ScoreCalculator.java`.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd analyzer && ./gradlew test --tests "dev.pluginguard.scoring.ScoreByAxisTest"`
Expected: PASS (3 tests).

- [ ] **Step 6: Run the existing scoring/security tests to confirm no regression**

Run: `cd analyzer && ./gradlew test --tests "dev.pluginguard.engine.*"`
Expected: PASS (all existing suites green — the legacy `score(...)` path is unchanged).

- [ ] **Step 7: Commit**

```bash
git add analyzer/src/main/java/dev/pluginguard/engine/model/AxisScore.java \
        analyzer/src/main/java/dev/pluginguard/scoring/ScoreCalculator.java \
        analyzer/src/test/java/dev/pluginguard/scoring/ScoreByAxisTest.java
git commit -m "feat(scoring): per-axis scoring (scoreByAxis) reusing the deduction model"
```

---

## Task 3: `Recommendation` + `RecommendationCalculator` (security veto)

**Files:**
- Create: `analyzer/src/main/java/dev/pluginguard/engine/model/RecommendationLevel.java`
- Create: `analyzer/src/main/java/dev/pluginguard/engine/model/Recommendation.java`
- Create: `analyzer/src/main/java/dev/pluginguard/scoring/RecommendationCalculator.java`
- Test: `analyzer/src/test/java/dev/pluginguard/scoring/RecommendationCalculatorTest.java`

**Interfaces:**
- Consumes: `Axis`, `AxisScore`, `Verdict`.
- Produces: `enum RecommendationLevel { SAFE_TO_INSTALL, INSTALL_WITH_CARE, RISKY, AVOID, DO_NOT_INSTALL }` with `displayName()`; `record Recommendation(RecommendationLevel level, String headline, List<String> perAxis)`; `Recommendation RecommendationCalculator.recommend(List<AxisScore> axes)`.

- [ ] **Step 1: Write the failing test**

```java
// analyzer/src/test/java/dev/pluginguard/scoring/RecommendationCalculatorTest.java
package dev.pluginguard.scoring;

import dev.pluginguard.engine.model.Axis;
import dev.pluginguard.engine.model.AxisScore;
import dev.pluginguard.engine.model.Recommendation;
import dev.pluginguard.engine.model.RecommendationLevel;
import dev.pluginguard.engine.model.SeverityCounts;
import dev.pluginguard.engine.model.Verdict;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class RecommendationCalculatorTest {

    private final RecommendationCalculator calc = new RecommendationCalculator();

    private static AxisScore axis(Axis a, Verdict v) {
        return new AxisScore(a, 50, v, new SeverityCounts(0, 0, 0, 0, 0), "x");
    }

    @Test
    void securityCriticalVetoesEverything() {
        Recommendation r = calc.recommend(List.of(
                axis(Axis.SECURITY, Verdict.CRITICAL_RISK),
                axis(Axis.PERFORMANCE, Verdict.MINIMAL_RISK)));
        assertThat(r.level()).isEqualTo(RecommendationLevel.DO_NOT_INSTALL);
    }

    @Test
    void securityHighIsAvoid() {
        Recommendation r = calc.recommend(List.of(axis(Axis.SECURITY, Verdict.HIGH_RISK)));
        assertThat(r.level()).isEqualTo(RecommendationLevel.AVOID);
    }

    @Test
    void performanceCriticalWithCleanSecurityIsAvoid() {
        Recommendation r = calc.recommend(List.of(
                axis(Axis.SECURITY, Verdict.MINIMAL_RISK),
                axis(Axis.PERFORMANCE, Verdict.CRITICAL_RISK)));
        assertThat(r.level()).isEqualTo(RecommendationLevel.AVOID);
        assertThat(r.headline().toLowerCase()).contains("performance");
    }

    @Test
    void allCleanIsSafeToInstall() {
        Recommendation r = calc.recommend(List.of(
                axis(Axis.SECURITY, Verdict.MINIMAL_RISK),
                axis(Axis.PERFORMANCE, Verdict.LOW_RISK)));
        assertThat(r.level()).isEqualTo(RecommendationLevel.SAFE_TO_INSTALL);
    }

    @Test
    void nonSecurityMediumIsInstallWithCare() {
        Recommendation r = calc.recommend(List.of(
                axis(Axis.SECURITY, Verdict.MINIMAL_RISK),
                axis(Axis.PERFORMANCE, Verdict.MEDIUM_RISK)));
        assertThat(r.level()).isEqualTo(RecommendationLevel.INSTALL_WITH_CARE);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd analyzer && ./gradlew test --tests "dev.pluginguard.scoring.RecommendationCalculatorTest"`
Expected: COMPILE FAILURE — types do not exist.

- [ ] **Step 3: Create `RecommendationLevel`**

```java
// analyzer/src/main/java/dev/pluginguard/engine/model/RecommendationLevel.java
package dev.pluginguard.engine.model;

/** Overall install guidance synthesized across axes (most to least favorable). */
public enum RecommendationLevel {
    SAFE_TO_INSTALL("Safe to install"),
    INSTALL_WITH_CARE("Install with care"),
    RISKY("Risky"),
    AVOID("Avoid"),
    DO_NOT_INSTALL("Do not install");

    private final String displayName;

    RecommendationLevel(String displayName) {
        this.displayName = displayName;
    }

    public String displayName() {
        return displayName;
    }
}
```

- [ ] **Step 4: Create `Recommendation`**

```java
// analyzer/src/main/java/dev/pluginguard/engine/model/Recommendation.java
package dev.pluginguard.engine.model;

import java.util.List;

/**
 * A combined, plain-language install recommendation across all populated axes. This is a
 * recommendation, not a guarantee — the per-axis breakdown is always shown alongside it.
 *
 * @param level    the headline guidance level
 * @param headline one-line reason naming the dominant axis
 * @param perAxis  one short line per populated axis
 */
public record Recommendation(RecommendationLevel level, String headline, List<String> perAxis) {

    public Recommendation {
        perAxis = perAxis == null ? List.of() : List.copyOf(perAxis);
    }
}
```

- [ ] **Step 5: Create `RecommendationCalculator`**

```java
// analyzer/src/main/java/dev/pluginguard/scoring/RecommendationCalculator.java
package dev.pluginguard.scoring;

import dev.pluginguard.engine.model.Axis;
import dev.pluginguard.engine.model.AxisScore;
import dev.pluginguard.engine.model.Recommendation;
import dev.pluginguard.engine.model.RecommendationLevel;
import dev.pluginguard.engine.model.Verdict;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/** Synthesizes per-axis verdicts into one install recommendation, with security holding veto power. */
@Component
public class RecommendationCalculator {

    public Recommendation recommend(List<AxisScore> axes) {
        Optional<AxisScore> security = axes.stream().filter(a -> a.axis() == Axis.SECURITY).findFirst();
        Verdict sec = security.map(AxisScore::verdict).orElse(Verdict.MINIMAL_RISK);

        List<String> perAxis = new ArrayList<>();
        for (AxisScore a : axes) {
            perAxis.add(a.axis().displayName() + ": " + a.verdict().getLabel() + " — " + a.headline());
        }

        // Security veto.
        if (sec == Verdict.CRITICAL_RISK) {
            return new Recommendation(RecommendationLevel.DO_NOT_INSTALL,
                    "Critical security risk — do not install this artifact.", perAxis);
        }
        if (sec == Verdict.HIGH_RISK) {
            return new Recommendation(RecommendationLevel.AVOID,
                    "High security risk — avoid unless you fully trust the source.", perAxis);
        }

        // Worst non-security axis drives the rest.
        AxisScore worst = axes.stream()
                .filter(a -> a.axis() != Axis.SECURITY)
                .max((x, y) -> Integer.compare(x.verdict().ordinal(), y.verdict().ordinal()))
                .orElse(null);
        Verdict other = worst == null ? Verdict.MINIMAL_RISK : worst.verdict();
        String axisName = worst == null ? "" : worst.axis().displayName().toLowerCase();

        if (other == Verdict.CRITICAL_RISK) {
            return new Recommendation(RecommendationLevel.AVOID,
                    "Security looks clean, but a critical " + axisName + " risk makes this unsafe to run as-is.",
                    perAxis);
        }
        if (other == Verdict.HIGH_RISK) {
            return new Recommendation(RecommendationLevel.RISKY,
                    "Security looks clean, but there is a high " + axisName + " risk — review before installing.",
                    perAxis);
        }
        if (other == Verdict.MEDIUM_RISK) {
            return new Recommendation(RecommendationLevel.INSTALL_WITH_CARE,
                    "No serious issues, but some " + axisName + " concerns — install with care.", perAxis);
        }
        return new Recommendation(RecommendationLevel.SAFE_TO_INSTALL,
                "No significant security or quality concerns were found in static analysis.", perAxis);
    }
}
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `cd analyzer && ./gradlew test --tests "dev.pluginguard.scoring.RecommendationCalculatorTest"`
Expected: PASS (5 tests).

- [ ] **Step 7: Commit**

```bash
git add analyzer/src/main/java/dev/pluginguard/engine/model/RecommendationLevel.java \
        analyzer/src/main/java/dev/pluginguard/engine/model/Recommendation.java \
        analyzer/src/main/java/dev/pluginguard/scoring/RecommendationCalculator.java \
        analyzer/src/test/java/dev/pluginguard/scoring/RecommendationCalculatorTest.java
git commit -m "feat(scoring): combined install recommendation with security veto"
```

---

## Task 4: Wire axes + recommendation into `ScanResult` and the engine

**Files:**
- Modify: `analyzer/src/main/java/dev/pluginguard/engine/model/ScanResult.java`
- Modify: `analyzer/src/main/java/dev/pluginguard/engine/AnalysisEngine.java`
- Modify: `analyzer/src/main/java/dev/pluginguard/api/DemoData.java`
- Modify: `analyzer/src/test/java/dev/pluginguard/engine/sandbox/Phase3SandboxTest.java:215`
- Test: `analyzer/src/test/java/dev/pluginguard/engine/MultiAxisEngineTest.java`

**Interfaces:**
- Consumes: `ScoreCalculator.scoreByAxis`, `RecommendationCalculator.recommend`, `AxisScore`, `Recommendation`.
- Produces: `ScanResult` gains trailing fields `List<AxisScore> axes`, `Recommendation recommendation`. Top-level `score`/`verdict` now come from the SECURITY `AxisScore`.

- [ ] **Step 1: Write the failing test**

```java
// analyzer/src/test/java/dev/pluginguard/engine/MultiAxisEngineTest.java
package dev.pluginguard.engine;

import dev.pluginguard.engine.model.Axis;
import dev.pluginguard.engine.model.ScanResult;
import dev.pluginguard.support.JarBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class MultiAxisEngineTest {

    @Autowired
    AnalysisEngine engine;

    @Test
    void everyReportHasASecurityAxisAndARecommendation() {
        byte[] jar = new JarBuilder().addClass("com/x/Plugin").build();
        ScanResult result = engine.analyze("ma1", "x.jar", jar);

        assertThat(result.axes()).isNotNull();
        assertThat(result.axes()).anyMatch(a -> a.axis() == Axis.SECURITY);
        assertThat(result.recommendation()).isNotNull();
        // Top-level score equals the SECURITY axis score (backward compatibility).
        int securityScore = result.axes().stream()
                .filter(a -> a.axis() == Axis.SECURITY).findFirst().orElseThrow().score();
        assertThat(result.score()).isEqualTo(securityScore);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd analyzer && ./gradlew test --tests "dev.pluginguard.engine.MultiAxisEngineTest"`
Expected: COMPILE FAILURE — `result.axes()` / `result.recommendation()` do not exist.

- [ ] **Step 3: Add the two fields to `ScanResult`**

Append `List<AxisScore> axes` and `Recommendation recommendation` to the record components (after `sandbox`), update the Javadoc tail, and thread them through `withSandbox`. Add imports `import dev.pluginguard.engine.model.AxisScore;` is unnecessary (same package); just reference `AxisScore` and `Recommendation` directly.

Replace the record header's closing components and the `withSandbox` method:

```java
        String engineVersion,
        SandboxReport sandbox,
        List<AxisScore> axes,
        Recommendation recommendation) {

    /** Returns a copy with the sandbox section (and, optionally, an updated verdict) replaced. */
    public ScanResult withSandbox(SandboxReport sandbox, Verdict verdict, List<String> notes) {
        return new ScanResult(id, fileName, sha256, sizeBytes, platform, artifactType, mainClass, mcApiVersion,
                score, verdict, obfuscationScore, counts, pluginInfo, findings, summaries, notes,
                analyzedAt, durationMs, engineVersion, sandbox, axes, recommendation);
    }
}
```

(Add `import dev.pluginguard.engine.model.AxisScore;` — actually `ScanResult` is in package `dev.pluginguard.engine.model`, so `AxisScore` and `Recommendation` need no import.)

- [ ] **Step 4: Assemble axes + recommendation in `AnalysisEngine`**

Inject `RecommendationCalculator`, bump the version, compute axes, derive the top-level score/verdict from the SECURITY axis, and pass the new fields. Edit `AnalysisEngine.java`:

Change the version constant:

```java
    public static final String ENGINE_VERSION = "0.2.0";
```

Add the field + constructor param:

```java
    private final ScoreCalculator scoreCalculator;
    private final RecommendationCalculator recommendationCalculator;

    public AnalysisEngine(JarLoader jarLoader, List<Analyzer> analyzers,
                          ScoreCalculator scoreCalculator,
                          RecommendationCalculator recommendationCalculator) {
        this.jarLoader = jarLoader;
        this.analyzers = analyzers;
        this.scoreCalculator = scoreCalculator;
        this.recommendationCalculator = recommendationCalculator;
    }
```

Replace the scoring/assembly block (currently lines ~71–106) with:

```java
        List<Finding> findings = ctx.findings().stream().sorted(FINDING_ORDER).toList();
        List<AxisScore> axes = scoreCalculator.scoreByAxis(findings);
        AxisScore security = axes.stream()
                .filter(a -> a.axis() == Axis.SECURITY)
                .findFirst()
                .orElse(null);
        int score = security != null ? security.score() : scoreCalculator.score(findings);
        SeverityCounts counts = SeverityCounts.from(findings);
        Verdict verdict = security != null ? security.verdict() : Verdict.from(score, counts);
        Recommendation recommendation = recommendationCalculator.recommend(axes);
        PluginInfo info = ctx.pluginInfo();

        Summaries summaries = new Summaries(
                ctx.network(), ctx.filesystem(), ctx.dependencies(),
                classScans.size(), ctx.methodCount());

        long duration = System.currentTimeMillis() - start;
        log.info("Analyzed '{}' ({} classes) -> score {} ({}) in {} ms",
                fileName, classScans.size(), score, verdict.getLabel(), duration);

        return new ScanResult(
                id,
                fileName,
                jar.sha256(),
                jar.sizeBytes(),
                ctx.platform(),
                ctx.artifactType(),
                info != null ? info.main() : null,
                info != null ? info.apiVersion() : null,
                score,
                verdict,
                ctx.obfuscationScore(),
                counts,
                info,
                findings,
                summaries,
                ctx.notes(),
                Instant.now(),
                duration,
                ENGINE_VERSION,
                null,
                axes,
                recommendation);
```

Add imports to `AnalysisEngine.java`: `import dev.pluginguard.engine.model.Axis;`, `import dev.pluginguard.engine.model.AxisScore;`, `import dev.pluginguard.engine.model.Recommendation;`, `import dev.pluginguard.scoring.RecommendationCalculator;`.

- [ ] **Step 5: Update `DemoData` to supply the new fields**

In `DemoData.sample()`, after the existing `findings` list, add a demo performance finding and build illustrative axes + a recommendation. Insert before `return new ScanResult(`:

```java
        // (extend the `findings` List.of(...) above with one performance finding)
        // Add to the findings list:
        //   Finding.builder("PERF_BLOCKING_IO_HOT_PATH", Category.PERFORMANCE, Severity.HIGH)
        //       .title("Database query on the server thread in a hot path")
        //       .description("Runs a synchronous database query from a frequently-fired event — this can stall the server tick under load.")
        //       .recommendation("Move the query to an async task and cache the result.")
        //       .location("dev.chatguard.listener.MoveListener#onMove")
        //       .evidence("java.sql.Statement.executeQuery")
        //       .scoreImpact(20).build()

        java.util.List<dev.pluginguard.engine.model.AxisScore> axes = java.util.List.of(
                new dev.pluginguard.engine.model.AxisScore(
                        dev.pluginguard.engine.model.Axis.SECURITY, 78,
                        Verdict.from(78, counts), counts, "1 serious security issue(s)"),
                new dev.pluginguard.engine.model.AxisScore(
                        dev.pluginguard.engine.model.Axis.PERFORMANCE, 55,
                        Verdict.MEDIUM_RISK, new SeverityCounts(0, 1, 0, 0, 0),
                        "1 serious performance issue(s)"));

        dev.pluginguard.engine.model.Recommendation recommendation =
                new dev.pluginguard.engine.model.Recommendation(
                        dev.pluginguard.engine.model.RecommendationLevel.INSTALL_WITH_CARE,
                        "Usable, but review the external webhook and the database query on the server thread.",
                        java.util.List.of(
                                "Security: Low Risk — 1 serious security issue(s)",
                                "Performance: Medium Risk — 1 serious performance issue(s)"));
```

Then add `axes, recommendation` as the final two arguments of the `new ScanResult(...)` call (after `sandbox`).

> NOTE: also add the `PERF_BLOCKING_IO_HOT_PATH` finding shown above to the `List.of(...)` of findings so the demo report contains a performance finding. (Fully-qualified `Category.PERFORMANCE` is already imported via the existing `Category` import.)

- [ ] **Step 6: Fix the test helper in `Phase3SandboxTest`**

`Phase3SandboxTest.java:215` constructs a `ScanResult` directly. Append the two new arguments. Change the tail of that constructor call from ending in the sandbox/`null` argument to also pass empty axes + a placeholder recommendation:

```java
                // ... existing arguments through the sandbox argument ...
                ,
                java.util.List.of(),
                new dev.pluginguard.engine.model.Recommendation(
                        dev.pluginguard.engine.model.RecommendationLevel.SAFE_TO_INSTALL, "test", java.util.List.of()));
```

(Place these as the final two arguments of that `new ScanResult(...)` call, matching the new record order.)

- [ ] **Step 7: Run the new test + the full suite**

Run: `cd analyzer && ./gradlew test`
Expected: PASS — `MultiAxisEngineTest` green, and all existing suites still green (the SECURITY axis reproduces the legacy score, so security regressions are unchanged).

- [ ] **Step 8: Commit**

```bash
git add analyzer/src/main/java/dev/pluginguard/engine/model/ScanResult.java \
        analyzer/src/main/java/dev/pluginguard/engine/AnalysisEngine.java \
        analyzer/src/main/java/dev/pluginguard/api/DemoData.java \
        analyzer/src/test/java/dev/pluginguard/engine/sandbox/Phase3SandboxTest.java \
        analyzer/src/test/java/dev/pluginguard/engine/MultiAxisEngineTest.java
git commit -m "feat(engine): assemble multi-axis scores + recommendation into ScanResult (v0.2.0)"
```

---

## Task 5: Extend `JarBuilder` for performance test scaffolding

**Files:**
- Modify: `analyzer/src/test/java/dev/pluginguard/support/JarBuilder.java`
- Test: `analyzer/src/test/java/dev/pluginguard/support/JarBuilderPerfScaffoldTest.java`

**Interfaces:**
- Produces on `JarBuilder`:
  - `addListenerClass(String internalName, String handlerName, String eventInternalName, List<Call> handlerCalls)` — a class implementing `org/bukkit/event/Listener` with a method `handlerName(L{event};)V` annotated `@org.bukkit.event.EventHandler` whose body invokes `handlerCalls` (each `INVOKESTATIC owner.name ()V`).
  - `addRunnableClass(String internalName, List<Call> runCalls)` — a class extending `org/bukkit/scheduler/BukkitRunnable` with `run()V` invoking `runCalls`.
  - `addClassExtending(String internalName, String superName, String methodName, List<Call> calls)` — generic superclass support.

- [ ] **Step 1: Write the failing test**

```java
// analyzer/src/test/java/dev/pluginguard/support/JarBuilderPerfScaffoldTest.java
package dev.pluginguard.support;

import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.bytecode.ClassScanner;
import dev.pluginguard.engine.model.ClassFile;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class JarBuilderPerfScaffoldTest {

    @Test
    void listenerClassHasInterfaceAndInvokesItsCalls() {
        byte[] jar = new JarBuilder()
                .addListenerClass("com/x/Listener", "onMove",
                        "org/bukkit/event/player/PlayerMoveEvent",
                        JarBuilder.calls(new JarBuilder.Call("com/x/Helper", "help")))
                .build();
        // Pull the class bytes back out and scan them.
        ClassScan scan = scanFromJar(jar, "com/x/Listener.class", "com/x/Listener");

        assertThat(scan.interfaces()).contains("org/bukkit/event/Listener");
        assertThat(scan.methods()).anyMatch(m -> m.name().equals("onMove"));
        assertThat(scan.invocations()).anyMatch(i ->
                i.owner().equals("com/x/Helper") && i.name().equals("help")
                        && i.callerMethod().equals("onMove"));
    }

    @Test
    void runnableClassExtendsBukkitRunnable() {
        byte[] jar = new JarBuilder()
                .addRunnableClass("com/x/Task",
                        JarBuilder.calls(new JarBuilder.Call("java/sql/DriverManager", "getConnection")))
                .build();
        ClassScan scan = scanFromJar(jar, "com/x/Task.class", "com/x/Task");
        assertThat(scan.superName()).isEqualTo("org/bukkit/scheduler/BukkitRunnable");
        assertThat(scan.invocations()).anyMatch(i -> i.owner().equals("java/sql/DriverManager"));
    }

    private static ClassScan scanFromJar(byte[] jar, String entry, String internalName) {
        try (var zis = new java.util.zip.ZipInputStream(new java.io.ByteArrayInputStream(jar))) {
            java.util.zip.ZipEntry e;
            while ((e = zis.getNextEntry()) != null) {
                if (e.getName().equals(entry)) {
                    return ClassScanner.scan(new ClassFile(internalName, zis.readAllBytes(), ""));
                }
            }
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
        throw new IllegalStateException("entry not found: " + entry);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd analyzer && ./gradlew test --tests "dev.pluginguard.support.JarBuilderPerfScaffoldTest"`
Expected: COMPILE FAILURE — `addListenerClass`/`addRunnableClass` do not exist.

- [ ] **Step 3: Add the new builder methods to `JarBuilder`**

Add these methods inside the `JarBuilder` class (next to the existing `addClass` methods):

```java
    /** A class implementing org/bukkit/event/Listener with an @EventHandler method taking one event. */
    public JarBuilder addListenerClass(String internalName, String handlerName,
                                       String eventInternalName, List<Call> handlerCalls) {
        entries.put(internalName + ".class",
                listenerClassBytes(internalName, handlerName, eventInternalName, handlerCalls));
        return this;
    }

    /** A class extending org/bukkit/scheduler/BukkitRunnable with a run()V body of the given calls. */
    public JarBuilder addRunnableClass(String internalName, List<Call> runCalls) {
        entries.put(internalName + ".class",
                superclassClassBytes(internalName, "org/bukkit/scheduler/BukkitRunnable", "run", runCalls));
        return this;
    }

    /** A class extending an arbitrary superclass with one method of the given calls. */
    public JarBuilder addClassExtending(String internalName, String superName,
                                        String methodName, List<Call> calls) {
        entries.put(internalName + ".class", superclassClassBytes(internalName, superName, methodName, calls));
        return this;
    }

    private static byte[] listenerClassBytes(String internalName, String handlerName,
                                             String eventInternalName, List<Call> calls) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object",
                new String[]{"org/bukkit/event/Listener"});
        emitDefaultCtor(cw);

        // public void handler(LEvent;) { <calls>; return; } annotated @EventHandler
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, handlerName,
                "(L" + eventInternalName + ";)V", null, null);
        mv.visitAnnotation("Lorg/bukkit/event/EventHandler;", true).visitEnd();
        mv.visitCode();
        for (Call c : calls) {
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, c.owner(), c.name(), "()V", false);
        }
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }

    private static byte[] superclassClassBytes(String internalName, String superName,
                                               String methodName, List<Call> calls) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, internalName, null, superName, null);
        emitDefaultCtorFor(cw, superName);

        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, methodName, "()V", null, null);
        mv.visitCode();
        for (Call c : calls) {
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, c.owner(), c.name(), "()V", false);
        }
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }

    private static void emitDefaultCtor(ClassWriter cw) {
        emitDefaultCtorFor(cw, "java/lang/Object");
    }

    private static void emitDefaultCtorFor(ClassWriter cw, String superName) {
        MethodVisitor ctor = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        ctor.visitCode();
        ctor.visitVarInsn(Opcodes.ALOAD, 0);
        ctor.visitMethodInsn(Opcodes.INVOKESPECIAL, superName, "<init>", "()V", false);
        ctor.visitInsn(Opcodes.RETURN);
        ctor.visitMaxs(0, 0);
        ctor.visitEnd();
    }
```

> NOTE: `superclassClassBytes` calls `super.<init>()V` on `BukkitRunnable`, which the analyzer never executes (ASM parsing only), so the missing real superclass is irrelevant.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd analyzer && ./gradlew test --tests "dev.pluginguard.support.JarBuilderPerfScaffoldTest"`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add analyzer/src/test/java/dev/pluginguard/support/JarBuilder.java \
        analyzer/src/test/java/dev/pluginguard/support/JarBuilderPerfScaffoldTest.java
git commit -m "test(support): JarBuilder scaffolding for listeners and BukkitRunnable tasks"
```

---

## Task 6: Capture method annotations in the ASM pass

**Files:**
- Modify: `analyzer/src/main/java/dev/pluginguard/engine/bytecode/MethodInfo.java`
- Modify: `analyzer/src/main/java/dev/pluginguard/engine/bytecode/ClassScanner.java`
- Test: `analyzer/src/test/java/dev/pluginguard/engine/bytecode/MethodAnnotationCaptureTest.java`

**Interfaces:**
- Produces: `MethodInfo` gains `List<String> annotations` (annotation descriptors, e.g. `Lorg/bukkit/event/EventHandler;`). Existing two-arg `MethodInfo(name, desc)` call sites keep compiling via a compact constructor default — OR are updated. (This plan updates the single construction site in `ClassScanner`.)

- [ ] **Step 1: Write the failing test**

```java
// analyzer/src/test/java/dev/pluginguard/engine/bytecode/MethodAnnotationCaptureTest.java
package dev.pluginguard.engine.bytecode;

import dev.pluginguard.engine.model.ClassFile;
import dev.pluginguard.support.JarBuilder;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class MethodAnnotationCaptureTest {

    @Test
    void eventHandlerAnnotationIsCaptured() {
        byte[] jar = new JarBuilder()
                .addListenerClass("com/x/L", "onMove",
                        "org/bukkit/event/player/PlayerMoveEvent", JarBuilder.calls())
                .build();
        ClassScan scan = scan(jar, "com/x/L.class", "com/x/L");

        MethodInfo handler = scan.methods().stream()
                .filter(m -> m.name().equals("onMove")).findFirst().orElseThrow();
        assertThat(handler.annotations()).contains("Lorg/bukkit/event/EventHandler;");
    }

    private static ClassScan scan(byte[] jar, String entry, String name) {
        try (var zis = new java.util.zip.ZipInputStream(new java.io.ByteArrayInputStream(jar))) {
            java.util.zip.ZipEntry e;
            while ((e = zis.getNextEntry()) != null) {
                if (e.getName().equals(entry)) {
                    return ClassScanner.scan(new ClassFile(name, zis.readAllBytes(), ""));
                }
            }
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
        throw new IllegalStateException("missing " + entry);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd analyzer && ./gradlew test --tests "dev.pluginguard.engine.bytecode.MethodAnnotationCaptureTest"`
Expected: COMPILE FAILURE — `MethodInfo.annotations()` does not exist.

- [ ] **Step 3: Add `annotations` to `MethodInfo`**

```java
// analyzer/src/main/java/dev/pluginguard/engine/bytecode/MethodInfo.java
package dev.pluginguard.engine.bytecode;

import java.util.List;

/** Minimal info about a declared method: name, descriptor, and annotation descriptors. */
public record MethodInfo(String name, String descriptor, List<String> annotations) {

    public MethodInfo {
        annotations = annotations == null ? List.of() : List.copyOf(annotations);
    }

    /** Backwards-compatible constructor for callers that don't track annotations. */
    public MethodInfo(String name, String descriptor) {
        this(name, descriptor, List.of());
    }
}
```

- [ ] **Step 4: Collect annotations in `ClassScanner`**

In `ClassScanner.scan(...)`, replace the method-collection line:

```java
        for (MethodNode method : node.methods) {
            methods.add(new MethodInfo(method.name, method.desc));
            scanMethod(node.name, method, constStringFields, invocations, strings);
        }
```

with:

```java
        for (MethodNode method : node.methods) {
            methods.add(new MethodInfo(method.name, method.desc, annotationDescriptors(method)));
            scanMethod(node.name, method, constStringFields, invocations, strings);
        }
```

Add this helper method to `ClassScanner`:

```java
    /** Descriptors of all (visible + invisible) annotations declared on a method. */
    private static List<String> annotationDescriptors(MethodNode method) {
        List<String> out = new ArrayList<>();
        if (method.visibleAnnotations != null) {
            for (var a : method.visibleAnnotations) {
                out.add(a.desc);
            }
        }
        if (method.invisibleAnnotations != null) {
            for (var a : method.invisibleAnnotations) {
                out.add(a.desc);
            }
        }
        return out;
    }
```

(`java.util.ArrayList` and `java.util.List` are already imported in `ClassScanner`.)

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd analyzer && ./gradlew test --tests "dev.pluginguard.engine.bytecode.MethodAnnotationCaptureTest"`
Expected: PASS.

- [ ] **Step 6: Run the full suite (MethodInfo is used by ObfuscationAnalyzer)**

Run: `cd analyzer && ./gradlew test`
Expected: PASS — the backwards-compatible `MethodInfo(name, desc)` keeps existing callers compiling.

- [ ] **Step 7: Commit**

```bash
git add analyzer/src/main/java/dev/pluginguard/engine/bytecode/MethodInfo.java \
        analyzer/src/main/java/dev/pluginguard/engine/bytecode/ClassScanner.java \
        analyzer/src/test/java/dev/pluginguard/engine/bytecode/MethodAnnotationCaptureTest.java
git commit -m "feat(bytecode): capture method annotation descriptors in the ASM pass"
```

---

## Task 7: `PerfSinkTable` — the perf-sensitive sink list

**Files:**
- Create: `analyzer/src/main/java/dev/pluginguard/engine/perf/PerfSinkTable.java`
- Test: `analyzer/src/test/java/dev/pluginguard/engine/perf/PerfSinkTableTest.java`

**Interfaces:**
- Produces: `enum SinkWeight { LIGHT, MODERATE, HEAVY, SEVERE }`; `record PerfSink(String title, SinkWeight weight, boolean alwaysBadOnMainThread, String recommendation)`; `static Optional<PerfSink> PerfSinkTable.match(String ownerInternalName, String methodName)`.

- [ ] **Step 1: Write the failing test**

```java
// analyzer/src/test/java/dev/pluginguard/engine/perf/PerfSinkTableTest.java
package dev.pluginguard.engine.perf;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

class PerfSinkTableTest {

    @Test
    void jdbcConnectionIsASevereAlwaysBadSink() {
        var sink = PerfSinkTable.match("java/sql/DriverManager", "getConnection").orElseThrow();
        assertThat(sink.weight()).isEqualTo(PerfSinkTable.SinkWeight.SEVERE);
        assertThat(sink.alwaysBadOnMainThread()).isTrue();
    }

    @Test
    void threadSleepIsHeavyAndAlwaysBad() {
        var sink = PerfSinkTable.match("java/lang/Thread", "sleep").orElseThrow();
        assertThat(sink.weight()).isEqualTo(PerfSinkTable.SinkWeight.HEAVY);
        assertThat(sink.alwaysBadOnMainThread()).isTrue();
    }

    @Test
    void ordinaryCallIsNotASink() {
        assertThat(PerfSinkTable.match("java/lang/String", "length")).isEmpty();
    }

    @Test
    void patternCompileIsModerate() {
        var sink = PerfSinkTable.match("java/util/regex/Pattern", "compile").orElseThrow();
        assertThat(sink.weight()).isEqualTo(PerfSinkTable.SinkWeight.MODERATE);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd analyzer && ./gradlew test --tests "dev.pluginguard.engine.perf.PerfSinkTableTest"`
Expected: COMPILE FAILURE — class missing.

- [ ] **Step 3: Implement `PerfSinkTable`**

```java
// analyzer/src/main/java/dev/pluginguard/engine/perf/PerfSinkTable.java
package dev.pluginguard.engine.perf;

import java.util.List;
import java.util.Optional;

/**
 * The table of method calls that are expensive on the server thread. Matching is by owner internal
 * name + method name (descriptor-independent), mirroring how the rest of the engine matches calls.
 */
public final class PerfSinkTable {

    public enum SinkWeight { LIGHT, MODERATE, HEAVY, SEVERE }

    /**
     * @param title                 short headline for the finding
     * @param weight                intrinsic cost
     * @param alwaysBadOnMainThread floor the severity at MEDIUM even in a low-frequency context
     * @param recommendation        what the admin/dev should do
     */
    public record PerfSink(String title, SinkWeight weight, boolean alwaysBadOnMainThread, String recommendation) {
    }

    private record Rule(String owner, String method, PerfSink sink) {
    }

    private static final String FIX_ASYNC =
            "Move this off the main server thread (e.g. an async task) and cache the result.";

    private static final List<Rule> RULES = List.of(
            // Blocking I/O — SEVERE, always bad on the main thread.
            rule("java/sql/DriverManager", "getConnection", "Opens a database connection on the server thread",
                    SinkWeight.SEVERE, true),
            rule("java/sql/Statement", "executeQuery", "Runs a database query on the server thread",
                    SinkWeight.SEVERE, true),
            rule("java/sql/Statement", "execute", "Runs a database statement on the server thread",
                    SinkWeight.SEVERE, true),
            rule("java/sql/Statement", "executeUpdate", "Runs a database update on the server thread",
                    SinkWeight.SEVERE, true),
            rule("java/sql/PreparedStatement", "execute", "Runs a prepared statement on the server thread",
                    SinkWeight.SEVERE, true),
            rule("java/sql/PreparedStatement", "executeQuery", "Runs a prepared query on the server thread",
                    SinkWeight.SEVERE, true),
            rule("java/net/HttpURLConnection", "getInputStream", "Blocking HTTP request on the server thread",
                    SinkWeight.SEVERE, true),
            rule("java/net/HttpURLConnection", "connect", "Blocking HTTP connect on the server thread",
                    SinkWeight.SEVERE, true),
            rule("java/net/http/HttpClient", "send", "Synchronous HTTP request on the server thread",
                    SinkWeight.SEVERE, true),
            rule("java/net/Socket", "connect", "Opens a network socket on the server thread",
                    SinkWeight.SEVERE, true),

            // Blocking waits — HEAVY, always bad on the main thread.
            rule("java/lang/Thread", "sleep", "Sleeps the calling thread", SinkWeight.HEAVY, true),
            rule("java/lang/Object", "wait", "Blocks the calling thread on a monitor", SinkWeight.HEAVY, true),
            rule("java/util/concurrent/Future", "get", "Blocks waiting for a future result", SinkWeight.HEAVY, true),
            rule("java/util/concurrent/CompletableFuture", "join", "Blocks joining a future", SinkWeight.HEAVY, true),
            rule("java/util/concurrent/CompletableFuture", "get", "Blocks waiting for a future", SinkWeight.HEAVY, true),

            // Synchronous world / chunk operations — HEAVY, always bad.
            rule("org/bukkit/World", "getChunkAt", "Loads/generates a chunk synchronously", SinkWeight.HEAVY, true),
            rule("org/bukkit/World", "loadChunk", "Loads a chunk synchronously", SinkWeight.HEAVY, true),

            // Hot-path anti-patterns — MODERATE.
            rule("java/util/regex/Pattern", "compile", "Compiles a regex in a hot path (should be a static field)",
                    SinkWeight.MODERATE, false),
            rule("org/bukkit/Bukkit", "getOnlinePlayers", "Iterates all online players in a hot path",
                    SinkWeight.MODERATE, false));

    private static Rule rule(String owner, String method, String title, SinkWeight w, boolean alwaysBad) {
        return new Rule(owner, method, new PerfSink(title, w, alwaysBad, FIX_ASYNC));
    }

    private PerfSinkTable() {
    }

    public static Optional<PerfSink> match(String ownerInternalName, String methodName) {
        for (Rule r : RULES) {
            if (r.owner.equals(ownerInternalName) && r.method.equals(methodName)) {
                return Optional.of(r.sink);
            }
        }
        return Optional.empty();
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd analyzer && ./gradlew test --tests "dev.pluginguard.engine.perf.PerfSinkTableTest"`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add analyzer/src/main/java/dev/pluginguard/engine/perf/PerfSinkTable.java \
        analyzer/src/test/java/dev/pluginguard/engine/perf/PerfSinkTableTest.java
git commit -m "feat(perf): perf-sensitive sink table"
```

---

## Task 8: Hot-path model — interface, heat, and Bukkit implementation

**Files:**
- Create: `analyzer/src/main/java/dev/pluginguard/engine/perf/Heat.java`
- Create: `analyzer/src/main/java/dev/pluginguard/engine/perf/HotEntrypoint.java`
- Create: `analyzer/src/main/java/dev/pluginguard/engine/perf/HotPathModel.java`
- Create: `analyzer/src/main/java/dev/pluginguard/engine/perf/BukkitHotPathModel.java`
- Test: `analyzer/src/test/java/dev/pluginguard/engine/perf/BukkitHotPathModelTest.java`

**Interfaces:**
- Produces:
  - `enum Heat { HOT, WARM, COOL }`.
  - `record HotEntrypoint(String classInternalName, String methodName, Heat heat)`.
  - `interface HotPathModel { boolean supports(ArtifactType t); List<HotEntrypoint> entrypoints(List<ClassScan> classes); }`.
  - `class BukkitHotPathModel implements HotPathModel`.

- [ ] **Step 1: Write the failing test**

```java
// analyzer/src/test/java/dev/pluginguard/engine/perf/BukkitHotPathModelTest.java
package dev.pluginguard.engine.perf;

import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.bytecode.ClassScanner;
import dev.pluginguard.engine.model.ArtifactType;
import dev.pluginguard.engine.model.ClassFile;
import dev.pluginguard.support.JarBuilder;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class BukkitHotPathModelTest {

    private final BukkitHotPathModel model = new BukkitHotPathModel();

    @Test
    void playerMoveHandlerIsAHotEntrypoint() {
        List<ClassScan> classes = scanAll(new JarBuilder()
                .addListenerClass("com/x/L", "onMove",
                        "org/bukkit/event/player/PlayerMoveEvent", JarBuilder.calls())
                .build());

        List<HotEntrypoint> eps = model.entrypoints(classes);
        assertThat(eps).anyMatch(e ->
                e.classInternalName().equals("com/x/L") && e.methodName().equals("onMove")
                        && e.heat() == Heat.HOT);
    }

    @Test
    void joinHandlerIsCoolNotHot() {
        List<ClassScan> classes = scanAll(new JarBuilder()
                .addListenerClass("com/x/L", "onJoin",
                        "org/bukkit/event/player/PlayerJoinEvent", JarBuilder.calls())
                .build());

        HotEntrypoint ep = model.entrypoints(classes).stream()
                .filter(e -> e.methodName().equals("onJoin")).findFirst().orElseThrow();
        assertThat(ep.heat()).isEqualTo(Heat.COOL);
    }

    @Test
    void supportsBukkitOnly() {
        assertThat(model.supports(ArtifactType.PLUGIN_BUKKIT)).isTrue();
        assertThat(model.supports(ArtifactType.MOD_FABRIC)).isFalse();
    }

    private static List<ClassScan> scanAll(byte[] jar) {
        List<ClassScan> out = new java.util.ArrayList<>();
        try (var zis = new java.util.zip.ZipInputStream(new java.io.ByteArrayInputStream(jar))) {
            java.util.zip.ZipEntry e;
            while ((e = zis.getNextEntry()) != null) {
                if (e.getName().endsWith(".class")) {
                    String internal = e.getName().substring(0, e.getName().length() - ".class".length());
                    out.add(ClassScanner.scan(new ClassFile(internal, zis.readAllBytes(), "")));
                }
            }
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
        return out;
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd analyzer && ./gradlew test --tests "dev.pluginguard.engine.perf.BukkitHotPathModelTest"`
Expected: COMPILE FAILURE — types missing.

- [ ] **Step 3: Create the small types**

```java
// analyzer/src/main/java/dev/pluginguard/engine/perf/Heat.java
package dev.pluginguard.engine.perf;

/** How frequently a hot entrypoint runs: HOT = per-tick/per-entity, WARM = frequent, COOL = occasional. */
public enum Heat { HOT, WARM, COOL }
```

```java
// analyzer/src/main/java/dev/pluginguard/engine/perf/HotEntrypoint.java
package dev.pluginguard.engine.perf;

/** A method that runs on the server thread frequently enough that expensive work in it hurts TPS. */
public record HotEntrypoint(String classInternalName, String methodName, Heat heat) {
}
```

```java
// analyzer/src/main/java/dev/pluginguard/engine/perf/HotPathModel.java
package dev.pluginguard.engine.perf;

import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.model.ArtifactType;

import java.util.List;

/** Artifact-family-specific detection of "hot path" entrypoints. */
public interface HotPathModel {

    boolean supports(ArtifactType type);

    List<HotEntrypoint> entrypoints(List<ClassScan> classes);
}
```

- [ ] **Step 4: Implement `BukkitHotPathModel`**

```java
// analyzer/src/main/java/dev/pluginguard/engine/perf/BukkitHotPathModel.java
package dev.pluginguard.engine.perf;

import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.bytecode.Invocation;
import dev.pluginguard.engine.bytecode.MethodInfo;
import dev.pluginguard.engine.model.ArtifactType;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Bukkit/Spigot/Paper hot paths: {@code @EventHandler} listener methods (heat by event type) and the
 * {@code run()} of {@link org.bukkit.scheduler.BukkitRunnable} subclasses registered via a *sync*
 * repeating scheduler. Registration via an async scheduler is intentionally NOT treated as hot.
 */
public class BukkitHotPathModel implements HotPathModel {

    private static final String LISTENER = "org/bukkit/event/Listener";
    private static final String EVENT_HANDLER = "Lorg/bukkit/event/EventHandler;";
    private static final String BUKKIT_RUNNABLE = "org/bukkit/scheduler/BukkitRunnable";

    /** Simple event class-name -> heat. Default for an unrecognized *Event is WARM. */
    private static final Map<String, Heat> EVENT_HEAT = Map.ofEntries(
            Map.entry("PlayerMoveEvent", Heat.HOT),
            Map.entry("EntityMoveEvent", Heat.HOT),
            Map.entry("VehicleMoveEvent", Heat.HOT),
            Map.entry("BlockPhysicsEvent", Heat.HOT),
            Map.entry("ProjectileHitEvent", Heat.HOT),
            Map.entry("EntityDamageEvent", Heat.HOT),
            Map.entry("EntityDamageByEntityEvent", Heat.HOT),
            Map.entry("FoodLevelChangeEvent", Heat.HOT),
            Map.entry("PlayerInteractEvent", Heat.HOT),
            Map.entry("AsyncPlayerChatEvent", Heat.WARM),
            Map.entry("InventoryClickEvent", Heat.WARM),
            Map.entry("BlockBreakEvent", Heat.WARM),
            Map.entry("BlockPlaceEvent", Heat.WARM),
            Map.entry("PlayerJoinEvent", Heat.COOL),
            Map.entry("PlayerQuitEvent", Heat.COOL),
            Map.entry("WorldLoadEvent", Heat.COOL));

    private static final List<String> SYNC_SCHEDULER_METHODS = List.of(
            "runTaskTimer", "scheduleSyncRepeatingTask", "runTask", "runTaskLater");

    @Override
    public boolean supports(ArtifactType type) {
        return type == ArtifactType.PLUGIN_BUKKIT;
    }

    @Override
    public List<HotEntrypoint> entrypoints(List<ClassScan> classes) {
        List<HotEntrypoint> out = new ArrayList<>();
        boolean hasSyncScheduler = classes.stream()
                .flatMap(c -> c.invocations().stream())
                .anyMatch(i -> SYNC_SCHEDULER_METHODS.contains(i.name()));

        for (ClassScan c : classes) {
            boolean isListener = c.interfaces().contains(LISTENER);
            boolean isRunnable = BUKKIT_RUNNABLE.equals(c.superName());

            for (MethodInfo m : c.methods()) {
                if (isListener && m.annotations().contains(EVENT_HANDLER)) {
                    out.add(new HotEntrypoint(c.internalName(), m.name(), eventHeat(m.descriptor())));
                }
                if (isRunnable && m.name().equals("run") && m.descriptor().equals("()V") && hasSyncScheduler) {
                    out.add(new HotEntrypoint(c.internalName(), "run", Heat.WARM));
                }
            }
        }
        return out;
    }

    /** Heat from the (single) event parameter's simple class name; unknown *Event -> WARM, else COOL. */
    private static Heat eventHeat(String methodDescriptor) {
        int start = methodDescriptor.indexOf('L');
        int end = methodDescriptor.indexOf(';');
        if (start < 0 || end < 0 || end < start) {
            return Heat.COOL;
        }
        String internal = methodDescriptor.substring(start + 1, end);
        String simple = internal.substring(internal.lastIndexOf('/') + 1);
        Heat known = EVENT_HEAT.get(simple);
        if (known != null) {
            return known;
        }
        return simple.endsWith("Event") ? Heat.WARM : Heat.COOL;
    }
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd analyzer && ./gradlew test --tests "dev.pluginguard.engine.perf.BukkitHotPathModelTest"`
Expected: PASS (3 tests).

- [ ] **Step 6: Commit**

```bash
git add analyzer/src/main/java/dev/pluginguard/engine/perf/Heat.java \
        analyzer/src/main/java/dev/pluginguard/engine/perf/HotEntrypoint.java \
        analyzer/src/main/java/dev/pluginguard/engine/perf/HotPathModel.java \
        analyzer/src/main/java/dev/pluginguard/engine/perf/BukkitHotPathModel.java \
        analyzer/src/test/java/dev/pluginguard/engine/perf/BukkitHotPathModelTest.java
git commit -m "feat(perf): hot-path model interface + Bukkit event/scheduler entrypoints"
```

---

## Task 9: `CallGraph` — intra-jar reachability from hot entrypoints

**Files:**
- Create: `analyzer/src/main/java/dev/pluginguard/engine/perf/CallGraph.java`
- Test: `analyzer/src/test/java/dev/pluginguard/engine/perf/CallGraphTest.java`

**Interfaces:**
- Consumes: `ClassScan.invocations()`, `HotEntrypoint`, `Heat`.
- Produces:
  - `record Reach(Heat heat, int distance)`.
  - `CallGraph(List<ClassScan> classes)` constructor builds the graph.
  - `Map<String, Reach> reachableFrom(List<HotEntrypoint> entrypoints, int maxDepth)` keyed by `classInternalName + "#" + methodName`, holding the min-distance/best-heat reach for every hot-reachable method.
  - `static String key(String classInternalName, String methodName)`.

- [ ] **Step 1: Write the failing test**

```java
// analyzer/src/test/java/dev/pluginguard/engine/perf/CallGraphTest.java
package dev.pluginguard.engine.perf;

import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.bytecode.ClassScanner;
import dev.pluginguard.engine.model.ClassFile;
import dev.pluginguard.support.JarBuilder;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class CallGraphTest {

    @Test
    void helperReachableFromHandlerWithIncreasedDistance() {
        // onMove -> Helper.help (intra-jar edge). help is reachable at distance 1.
        List<ClassScan> classes = scanAll(new JarBuilder()
                .addListenerClass("com/x/L", "onMove", "org/bukkit/event/player/PlayerMoveEvent",
                        JarBuilder.calls(new JarBuilder.Call("com/x/Helper", "help")))
                .addClass("com/x/Helper", "help", JarBuilder.calls(
                        new JarBuilder.Call("java/sql/DriverManager", "getConnection")), List.of())
                .build());

        CallGraph graph = new CallGraph(classes);
        Map<String, CallGraph.Reach> reach = graph.reachableFrom(
                List.of(new HotEntrypoint("com/x/L", "onMove", Heat.HOT)), 5);

        assertThat(reach).containsKey(CallGraph.key("com/x/L", "onMove"));
        CallGraph.Reach helper = reach.get(CallGraph.key("com/x/Helper", "help"));
        assertThat(helper).isNotNull();
        assertThat(helper.distance()).isEqualTo(1);
        assertThat(helper.heat()).isEqualTo(Heat.HOT);
    }

    @Test
    void coldMethodNotReachableFromHotEntrypoint() {
        List<ClassScan> classes = scanAll(new JarBuilder()
                .addListenerClass("com/x/L", "onMove", "org/bukkit/event/player/PlayerMoveEvent",
                        JarBuilder.calls())
                .addClass("com/x/Plugin", "onEnable", JarBuilder.calls(
                        new JarBuilder.Call("java/sql/DriverManager", "getConnection")), List.of())
                .build());

        CallGraph graph = new CallGraph(classes);
        Map<String, CallGraph.Reach> reach = graph.reachableFrom(
                List.of(new HotEntrypoint("com/x/L", "onMove", Heat.HOT)), 5);

        assertThat(reach).doesNotContainKey(CallGraph.key("com/x/Plugin", "onEnable"));
    }

    @Test
    void recursionTerminates() {
        // self-recursive method must not loop forever.
        List<ClassScan> classes = scanAll(new JarBuilder()
                .addClass("com/x/R", "loop", JarBuilder.calls(new JarBuilder.Call("com/x/R", "loop")), List.of())
                .build());
        CallGraph graph = new CallGraph(classes);
        Map<String, CallGraph.Reach> reach = graph.reachableFrom(
                List.of(new HotEntrypoint("com/x/R", "loop", Heat.WARM)), 5);
        assertThat(reach).containsKey(CallGraph.key("com/x/R", "loop"));
    }

    private static List<ClassScan> scanAll(byte[] jar) {
        List<ClassScan> out = new java.util.ArrayList<>();
        try (var zis = new java.util.zip.ZipInputStream(new java.io.ByteArrayInputStream(jar))) {
            java.util.zip.ZipEntry e;
            while ((e = zis.getNextEntry()) != null) {
                if (e.getName().endsWith(".class")) {
                    String internal = e.getName().substring(0, e.getName().length() - ".class".length());
                    out.add(ClassScanner.scan(new ClassFile(internal, zis.readAllBytes(), "")));
                }
            }
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
        return out;
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd analyzer && ./gradlew test --tests "dev.pluginguard.engine.perf.CallGraphTest"`
Expected: COMPILE FAILURE — `CallGraph` missing.

- [ ] **Step 3: Implement `CallGraph`**

```java
// analyzer/src/main/java/dev/pluginguard/engine/perf/CallGraph.java
package dev.pluginguard.engine.perf;

import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.bytecode.Invocation;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * An intra-jar call graph built from captured invocations. A node is a method, keyed by
 * {@code classInternalName + "#" + methodName} (descriptor-less, matching {@link Invocation}'s
 * caller identity). Edges point from a caller method to every in-jar callee method with the called
 * name. Reachability is a bounded BFS from the hot entrypoints; each reached node keeps the best
 * (highest) heat and the shortest distance found.
 */
public final class CallGraph {

    /** Reachability info for one method: the inherited heat and the shortest call distance. */
    public record Reach(Heat heat, int distance) {
    }

    /** Method names declared in the jar, grouped by owner internal name. */
    private final Map<String, Set<String>> methodsByOwner = new HashMap<>();
    /** Adjacency: caller node key -> set of in-jar callee node keys. */
    private final Map<String, Set<String>> edges = new HashMap<>();

    public CallGraph(List<ClassScan> classes) {
        Set<String> jarOwners = new HashSet<>();
        for (ClassScan c : classes) {
            jarOwners.add(c.internalName());
            Set<String> names = methodsByOwner.computeIfAbsent(c.internalName(), k -> new HashSet<>());
            c.methods().forEach(m -> names.add(m.name()));
        }
        for (ClassScan c : classes) {
            for (Invocation inv : c.invocations()) {
                if (!jarOwners.contains(inv.owner())) {
                    continue; // callee is a library/JDK class — not a graph edge
                }
                String from = key(inv.callerClass(), inv.callerMethod());
                String to = key(inv.owner(), inv.name());
                edges.computeIfAbsent(from, k -> new HashSet<>()).add(to);
            }
        }
    }

    /** Stable node key for (class, method). */
    public static String key(String classInternalName, String methodName) {
        return classInternalName + "#" + methodName;
    }

    /**
     * BFS from each hot entrypoint up to {@code maxDepth}. The returned map holds every reachable
     * method (including the entrypoints at distance 0) with its best heat and shortest distance.
     */
    public Map<String, Reach> reachableFrom(List<HotEntrypoint> entrypoints, int maxDepth) {
        Map<String, Reach> result = new HashMap<>();
        Deque<String> queue = new ArrayDeque<>();
        Map<String, Heat> entryHeat = new HashMap<>();

        for (HotEntrypoint ep : entrypoints) {
            String k = key(ep.classInternalName(), ep.methodName());
            // Seed; if seen twice keep the hotter.
            if (!result.containsKey(k) || hotter(ep.heat(), result.get(k).heat())) {
                result.put(k, new Reach(ep.heat(), 0));
                entryHeat.put(k, ep.heat());
                queue.add(k);
            }
        }

        while (!queue.isEmpty()) {
            String node = queue.poll();
            Reach here = result.get(node);
            if (here.distance() >= maxDepth) {
                continue;
            }
            for (String next : edges.getOrDefault(node, Set.of())) {
                Reach existing = result.get(next);
                int nextDist = here.distance() + 1;
                if (existing == null || nextDist < existing.distance() || hotter(here.heat(), existing.heat())) {
                    result.put(next, new Reach(here.heat(), Math.min(nextDist,
                            existing == null ? nextDist : existing.distance())));
                    queue.add(next);
                }
            }
        }
        return result;
    }

    private static boolean hotter(Heat a, Heat b) {
        return a.ordinal() < b.ordinal(); // HOT(0) < WARM(1) < COOL(2)
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd analyzer && ./gradlew test --tests "dev.pluginguard.engine.perf.CallGraphTest"`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add analyzer/src/main/java/dev/pluginguard/engine/perf/CallGraph.java \
        analyzer/src/test/java/dev/pluginguard/engine/perf/CallGraphTest.java
git commit -m "feat(perf): intra-jar call graph with bounded hot-path reachability"
```

---

## Task 10: `PerformanceAnalyzer` — the Bukkit path + severity formula + datapack re-route

**Files:**
- Create: `analyzer/src/main/java/dev/pluginguard/engine/analyzers/PerformanceAnalyzer.java`
- Test: `analyzer/src/test/java/dev/pluginguard/engine/PerformanceAnalyzerTest.java`

**Interfaces:**
- Consumes: `Analyzer`, `AnalysisContext` (`classScans()`, `artifactType()`, `findings()`, `add(...)`), `HotPathModel`+`BukkitHotPathModel`, `CallGraph`, `PerfSinkTable`, `Heat`, `Category.PERFORMANCE`, `Severity`, `Finding`.
- Produces: `@Component @Order(70) class PerformanceAnalyzer implements Analyzer`. Emits `Finding`s with `ruleId` `PERF_*` and `category = PERFORMANCE`. Re-routes data-pack lag findings as `PERF_DATAPACK_LAG_LOOP`.

- [ ] **Step 1: Write the failing test**

```java
// analyzer/src/test/java/dev/pluginguard/engine/PerformanceAnalyzerTest.java
package dev.pluginguard.engine;

import dev.pluginguard.engine.model.Axis;
import dev.pluginguard.engine.model.Category;
import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.ScanResult;
import dev.pluginguard.engine.model.Severity;
import dev.pluginguard.support.JarBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class PerformanceAnalyzerTest {

    @Autowired
    AnalysisEngine engine;

    private static byte[] pluginYml(JarBuilder b, String main) {
        return b.addResource("plugin.yml",
                "name: T\nversion: 1.0\nmain: " + main + "\napi-version: 1.21\n").build();
    }

    @Test
    void jdbcInPlayerMoveIsCriticalPerformanceFinding() {
        byte[] jar = pluginYml(new JarBuilder()
                .addClass("com/x/Plugin")
                .addListenerClass("com/x/L", "onMove", "org/bukkit/event/player/PlayerMoveEvent",
                        JarBuilder.calls(new JarBuilder.Call("java/sql/DriverManager", "getConnection"))),
                "com.x.Plugin");

        ScanResult result = engine.analyze("p1", "t.jar", jar);

        Finding perf = result.findings().stream()
                .filter(f -> f.category() == Category.PERFORMANCE).findFirst().orElse(null);
        assertThat(perf).isNotNull();
        assertThat(perf.severity()).isEqualTo(Severity.CRITICAL);
        assertThat(result.axes()).anyMatch(a -> a.axis() == Axis.PERFORMANCE);
    }

    @Test
    void jdbcInOnEnableIsNotAPerformanceFinding() {
        byte[] jar = pluginYml(new JarBuilder()
                .addClass("com/x/Plugin", "onEnable",
                        JarBuilder.calls(new JarBuilder.Call("java/sql/DriverManager", "getConnection")), List.of()),
                "com.x.Plugin");

        ScanResult result = engine.analyze("p2", "t.jar", jar);

        assertThat(result.findings()).noneMatch(f -> f.category() == Category.PERFORMANCE);
    }

    @Test
    void asyncWrappedJdbcIsNotFlagged() {
        // A BukkitRunnable subclass with JDBC in run(), but registered ONLY via async scheduler.
        byte[] jar = pluginYml(new JarBuilder()
                .addRunnableClass("com/x/Task",
                        JarBuilder.calls(new JarBuilder.Call("java/sql/DriverManager", "getConnection")))
                .addClass("com/x/Plugin", "onEnable",
                        JarBuilder.calls(new JarBuilder.Call(
                                "org/bukkit/scheduler/BukkitRunnable", "runTaskTimerAsynchronously")), List.of()),
                "com.x.Plugin");

        ScanResult result = engine.analyze("p3", "t.jar", jar);

        assertThat(result.findings()).noneMatch(f -> f.category() == Category.PERFORMANCE);
    }

    @Test
    void benignPluginHasNoPerformanceFindings() {
        byte[] jar = pluginYml(new JarBuilder()
                .addClass("com/x/Plugin")
                .addListenerClass("com/x/L", "onJoin", "org/bukkit/event/player/PlayerJoinEvent",
                        JarBuilder.calls()),
                "com.x.Plugin");

        ScanResult result = engine.analyze("p4", "t.jar", jar);
        assertThat(result.findings()).noneMatch(f -> f.category() == Category.PERFORMANCE);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd analyzer && ./gradlew test --tests "dev.pluginguard.engine.PerformanceAnalyzerTest"`
Expected: FAIL — no PERFORMANCE findings produced (analyzer doesn't exist yet).

- [ ] **Step 3: Implement `PerformanceAnalyzer`**

```java
// analyzer/src/main/java/dev/pluginguard/engine/analyzers/PerformanceAnalyzer.java
package dev.pluginguard.engine.analyzers;

import dev.pluginguard.engine.AnalysisContext;
import dev.pluginguard.engine.Analyzer;
import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.bytecode.Invocation;
import dev.pluginguard.engine.model.Category;
import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.Severity;
import dev.pluginguard.engine.perf.BukkitHotPathModel;
import dev.pluginguard.engine.perf.CallGraph;
import dev.pluginguard.engine.perf.ForgeHotPathModel;
import dev.pluginguard.engine.perf.FabricHotPathModel;
import dev.pluginguard.engine.perf.Heat;
import dev.pluginguard.engine.perf.HotEntrypoint;
import dev.pluginguard.engine.perf.HotPathModel;
import dev.pluginguard.engine.perf.PerfSinkTable;
import dev.pluginguard.engine.perf.PerfSinkTable.PerfSink;
import dev.pluginguard.engine.perf.PerfSinkTable.SinkWeight;
import dev.pluginguard.engine.perf.ProxyHotPathModel;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/**
 * Performance (lag-risk) analysis. Picks the hot-path model for the artifact, builds an intra-jar
 * call graph, marks the methods reachable from hot entrypoints, and reports perf-sensitive sinks
 * found in those reachable methods, scaling severity by sink weight, context heat and call distance
 * (Hybrid C). Also mirrors data-pack lag-loop findings onto the Performance axis.
 *
 * <p>Runs after {@code PackAnalyzer} (@Order 50) so its data-pack findings exist, and before the
 * correlation pass (@Order 1000).
 */
@Component
@Order(70)
public class PerformanceAnalyzer implements Analyzer {

    private static final int MAX_DEPTH = 5;

    private final List<HotPathModel> models = List.of(
            new BukkitHotPathModel(),
            new ForgeHotPathModel(),
            new FabricHotPathModel(),
            new ProxyHotPathModel());

    @Override
    public String name() {
        return "PerformanceAnalyzer";
    }

    @Override
    public void analyze(AnalysisContext ctx) {
        mirrorDataPackLagLoops(ctx);

        List<ClassScan> classes = ctx.classScans();
        if (classes.isEmpty()) {
            return;
        }
        HotPathModel model = models.stream()
                .filter(m -> m.supports(ctx.artifactType()))
                .findFirst().orElse(null);
        if (model == null) {
            return;
        }
        List<HotEntrypoint> entrypoints = model.entrypoints(classes);
        if (entrypoints.isEmpty()) {
            return;
        }

        CallGraph graph = new CallGraph(classes);
        Map<String, CallGraph.Reach> reachable = graph.reachableFrom(entrypoints, MAX_DEPTH);

        for (ClassScan c : classes) {
            for (Invocation inv : c.invocations()) {
                CallGraph.Reach reach = reachable.get(CallGraph.key(inv.callerClass(), inv.callerMethod()));
                if (reach == null) {
                    continue; // not on a hot path — cold-path suppression
                }
                PerfSinkTable.match(inv.owner(), inv.name()).ifPresent(sink ->
                        ctx.add(finding(c, inv, sink, reach)));
            }
        }
    }

    private static Finding finding(ClassScan c, Invocation inv, PerfSink sink, CallGraph.Reach reach) {
        Severity severity = severity(sink, reach);
        String where = inv.callerClass().replace('/', '.') + "#" + inv.callerMethod();
        String distanceNote = reach.distance() == 0
                ? "directly in a hot path"
                : "reachable " + reach.distance() + " call(s) deep from a hot path";
        return Finding.builder("PERF_" + ruleSuffix(inv), Category.PERFORMANCE, severity)
                .title(sink.title())
                .description(sink.title() + " — " + distanceNote
                        + " (context frequency: " + reach.heat().name().toLowerCase() + "). "
                        + "Expensive work on the server thread stalls the tick and lowers TPS under load.")
                .recommendation(sink.recommendation())
                .location(where)
                .evidence(inv.ownerDotted() + "." + inv.name())
                .scoreImpact(scoreImpact(severity))
                .nestedPath(c.nestedPath())
                .build();
    }

    private static String ruleSuffix(Invocation inv) {
        // Stable-ish suffix per sink: last path segment of the owner, uppercased.
        String owner = inv.owner();
        String tail = owner.substring(owner.lastIndexOf('/') + 1).toUpperCase();
        return tail + "_" + inv.name().toUpperCase();
    }

    /**
     * Severity = base(weight) + heatAdjust − distanceDecay, floored at MEDIUM for always-bad sinks,
     * clamped to LOW..CRITICAL.
     */
    private static Severity severity(PerfSink sink, CallGraph.Reach reach) {
        int level = baseLevel(sink.weight());           // LIGHT=1 .. SEVERE=4
        level += switch (reach.heat()) {
            case HOT -> 1;
            case WARM -> 0;
            case COOL -> -1;
        };
        level -= reach.distance() / 2;                  // 0–1 no decay, 2–3 −1, 4–5 −2
        if (sink.alwaysBadOnMainThread()) {
            level = Math.max(level, 2);                 // floor at MEDIUM
        }
        level = Math.max(1, Math.min(4, level));
        return switch (level) {
            case 4 -> Severity.CRITICAL;
            case 3 -> Severity.HIGH;
            case 2 -> Severity.MEDIUM;
            default -> Severity.LOW;
        };
    }

    private static int baseLevel(SinkWeight w) {
        return switch (w) {
            case LIGHT -> 1;
            case MODERATE -> 2;
            case HEAVY -> 3;
            case SEVERE -> 4;
        };
    }

    private static int scoreImpact(Severity severity) {
        return switch (severity) {
            case CRITICAL -> 35;
            case HIGH -> 20;
            case MEDIUM -> 10;
            case LOW -> 5;
            case INFO -> 0;
        };
    }

    /** Mirror existing data-pack lag-loop findings onto the Performance axis (no bytecode involved). */
    private static void mirrorDataPackLagLoops(AnalysisContext ctx) {
        boolean hasLagLoop = ctx.findings().stream().anyMatch(f -> f.ruleId().equals("DP_SELF_RECURSION"));
        if (!hasLagLoop) {
            return;
        }
        ctx.add(Finding.builder("PERF_DATAPACK_LAG_LOOP", Category.PERFORMANCE, Severity.HIGH)
                .title("Self-recursive data-pack function (lag machine)")
                .description("A data-pack function calls itself with no visible terminating guard. Unbounded "
                        + "function recursion runs as fast as the server can manage and will lag or freeze it.")
                .recommendation("Confirm the recursion terminates via a score/condition check before installing.")
                .scoreImpact(20)
                .build());
    }
}
```

> NOTE: `ForgeHotPathModel`, `FabricHotPathModel`, and `ProxyHotPathModel` are referenced here but
> created in Task 11. To keep this task compiling on its own, create **stub** versions first (see the
> next step), then flesh them out in Task 11.

- [ ] **Step 4: Create minimal stubs for the other three models (so Task 10 compiles)**

```java
// analyzer/src/main/java/dev/pluginguard/engine/perf/ForgeHotPathModel.java
package dev.pluginguard.engine.perf;

import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.model.ArtifactType;
import java.util.List;

public class ForgeHotPathModel implements HotPathModel {
    @Override public boolean supports(ArtifactType t) {
        return t == ArtifactType.MOD_FORGE || t == ArtifactType.MOD_NEOFORGE;
    }
    @Override public List<HotEntrypoint> entrypoints(List<ClassScan> classes) { return List.of(); }
}
```

```java
// analyzer/src/main/java/dev/pluginguard/engine/perf/FabricHotPathModel.java
package dev.pluginguard.engine.perf;

import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.model.ArtifactType;
import java.util.List;

public class FabricHotPathModel implements HotPathModel {
    @Override public boolean supports(ArtifactType t) {
        return t == ArtifactType.MOD_FABRIC || t == ArtifactType.MOD_QUILT;
    }
    @Override public List<HotEntrypoint> entrypoints(List<ClassScan> classes) { return List.of(); }
}
```

```java
// analyzer/src/main/java/dev/pluginguard/engine/perf/ProxyHotPathModel.java
package dev.pluginguard.engine.perf;

import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.model.ArtifactType;
import java.util.List;

public class ProxyHotPathModel implements HotPathModel {
    @Override public boolean supports(ArtifactType t) {
        return t == ArtifactType.PLUGIN_BUNGEE || t == ArtifactType.PLUGIN_VELOCITY;
    }
    @Override public List<HotEntrypoint> entrypoints(List<ClassScan> classes) { return List.of(); }
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd analyzer && ./gradlew test --tests "dev.pluginguard.engine.PerformanceAnalyzerTest"`
Expected: PASS (4 tests).

- [ ] **Step 6: Run the full suite (no false positives on existing benign cases)**

Run: `cd analyzer && ./gradlew test`
Expected: PASS — existing benign tests still see no Critical and now no spurious PERFORMANCE findings.

- [ ] **Step 7: Commit**

```bash
git add analyzer/src/main/java/dev/pluginguard/engine/analyzers/PerformanceAnalyzer.java \
        analyzer/src/main/java/dev/pluginguard/engine/perf/ForgeHotPathModel.java \
        analyzer/src/main/java/dev/pluginguard/engine/perf/FabricHotPathModel.java \
        analyzer/src/main/java/dev/pluginguard/engine/perf/ProxyHotPathModel.java \
        analyzer/src/test/java/dev/pluginguard/engine/PerformanceAnalyzerTest.java
git commit -m "feat(perf): PerformanceAnalyzer — Bukkit hot-path lag detection + severity model"
```

---

## Task 11: Flesh out Forge / Fabric / Proxy hot-path models

**Files:**
- Modify: `analyzer/src/main/java/dev/pluginguard/engine/perf/ForgeHotPathModel.java`
- Modify: `analyzer/src/main/java/dev/pluginguard/engine/perf/FabricHotPathModel.java`
- Modify: `analyzer/src/main/java/dev/pluginguard/engine/perf/ProxyHotPathModel.java`
- Test: `analyzer/src/test/java/dev/pluginguard/engine/perf/OtherHotPathModelsTest.java`

**Interfaces:**
- Produces: real `entrypoints(...)` for the three models.
  - Forge: methods annotated `Lnet/minecraftforge/eventbus/api/SubscribeEvent;` whose parameter type simple-name contains `Tick` → `HOT`, otherwise `WARM`.
  - Fabric: methods annotated `Lnet/fabricmc/api/Environment;`? No — Fabric tick callbacks are registered, not annotated. Detect a `run`/`on*Tick` method in a class implementing a `*TickEvents$*` or `ServerTickEvents` interface; **simpler, deterministic rule:** a method named `onEndTick` or `onStartTick` (the `ServerTickEvents.EndTick`/`StartTick` functional-interface method) in any class → `HOT`. (Documented heuristic.)
  - Proxy: methods annotated `Lnet/md_5/bungee/event/EventHandler;` (Bungee) or `Lcom/velocitypowered/api/event/Subscribe;` (Velocity) → `WARM`.

- [ ] **Step 1: Write the failing test**

```java
// analyzer/src/test/java/dev/pluginguard/engine/perf/OtherHotPathModelsTest.java
package dev.pluginguard.engine.perf;

import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.bytecode.MethodInfo;
import dev.pluginguard.engine.model.ArtifactType;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class OtherHotPathModelsTest {

    /** A hand-built ClassScan, bypassing JarBuilder, for annotation-only model tests. */
    private static ClassScan classWith(String internalName, MethodInfo... methods) {
        return new ClassScan(internalName, "java/lang/Object", List.of(), 0, true,
                List.of(methods), List.of(), List.of(), "", List.of());
    }

    @Test
    void forgeTickSubscriberIsHot() {
        ClassScan c = classWith("com/m/Handler",
                new MethodInfo("onTick", "(Lnet/minecraftforge/event/TickEvent$ServerTickEvent;)V",
                        List.of("Lnet/minecraftforge/eventbus/api/SubscribeEvent;")));
        List<HotEntrypoint> eps = new ForgeHotPathModel().entrypoints(List.of(c));
        assertThat(eps).anyMatch(e -> e.methodName().equals("onTick") && e.heat() == Heat.HOT);
    }

    @Test
    void fabricEndTickCallbackIsHot() {
        ClassScan c = classWith("com/m/Mod",
                new MethodInfo("onEndTick", "(Lnet/minecraft/server/MinecraftServer;)V", List.of()));
        List<HotEntrypoint> eps = new FabricHotPathModel().entrypoints(List.of(c));
        assertThat(eps).anyMatch(e -> e.methodName().equals("onEndTick") && e.heat() == Heat.HOT);
    }

    @Test
    void velocitySubscriberIsWarm() {
        ClassScan c = classWith("com/m/Listener",
                new MethodInfo("onPing", "(Lcom/velocitypowered/api/event/proxy/ProxyPingEvent;)V",
                        List.of("Lcom/velocitypowered/api/event/Subscribe;")));
        List<HotEntrypoint> eps = new ProxyHotPathModel().entrypoints(List.of(c));
        assertThat(eps).anyMatch(e -> e.methodName().equals("onPing") && e.heat() == Heat.WARM);
    }

    @Test
    void modelsSupportTheRightArtifacts() {
        assertThat(new ForgeHotPathModel().supports(ArtifactType.MOD_NEOFORGE)).isTrue();
        assertThat(new FabricHotPathModel().supports(ArtifactType.MOD_QUILT)).isTrue();
        assertThat(new ProxyHotPathModel().supports(ArtifactType.PLUGIN_VELOCITY)).isTrue();
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd analyzer && ./gradlew test --tests "dev.pluginguard.engine.perf.OtherHotPathModelsTest"`
Expected: FAIL — stubs return empty lists.

- [ ] **Step 3: Implement the three models**

Replace the body of `ForgeHotPathModel`:

```java
package dev.pluginguard.engine.perf;

import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.bytecode.MethodInfo;
import dev.pluginguard.engine.model.ArtifactType;

import java.util.ArrayList;
import java.util.List;

/** Forge/NeoForge hot paths: @SubscribeEvent methods, hottest when the event is a tick event. */
public class ForgeHotPathModel implements HotPathModel {

    private static final String SUBSCRIBE_EVENT = "Lnet/minecraftforge/eventbus/api/SubscribeEvent;";

    @Override
    public boolean supports(ArtifactType t) {
        return t == ArtifactType.MOD_FORGE || t == ArtifactType.MOD_NEOFORGE;
    }

    @Override
    public List<HotEntrypoint> entrypoints(List<ClassScan> classes) {
        List<HotEntrypoint> out = new ArrayList<>();
        for (ClassScan c : classes) {
            for (MethodInfo m : c.methods()) {
                if (!m.annotations().contains(SUBSCRIBE_EVENT)) {
                    continue;
                }
                boolean tick = m.descriptor().contains("Tick");
                out.add(new HotEntrypoint(c.internalName(), m.name(), tick ? Heat.HOT : Heat.WARM));
            }
        }
        return out;
    }
}
```

Replace the body of `FabricHotPathModel`:

```java
package dev.pluginguard.engine.perf;

import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.bytecode.MethodInfo;
import dev.pluginguard.engine.model.ArtifactType;

import java.util.ArrayList;
import java.util.List;

/**
 * Fabric/Quilt hot paths. Fabric tick callbacks are registered as lambdas, not annotated, so we
 * match the conventional functional-interface method names for the per-tick callbacks
 * ({@code ServerTickEvents.EndTick#onEndTick}, {@code StartTick#onStartTick}). Best-effort heuristic.
 */
public class FabricHotPathModel implements HotPathModel {

    private static final List<String> TICK_METHODS = List.of("onEndTick", "onStartTick");

    @Override
    public boolean supports(ArtifactType t) {
        return t == ArtifactType.MOD_FABRIC || t == ArtifactType.MOD_QUILT;
    }

    @Override
    public List<HotEntrypoint> entrypoints(List<ClassScan> classes) {
        List<HotEntrypoint> out = new ArrayList<>();
        for (ClassScan c : classes) {
            for (MethodInfo m : c.methods()) {
                if (TICK_METHODS.contains(m.name())) {
                    out.add(new HotEntrypoint(c.internalName(), m.name(), Heat.HOT));
                }
            }
        }
        return out;
    }
}
```

Replace the body of `ProxyHotPathModel`:

```java
package dev.pluginguard.engine.perf;

import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.bytecode.MethodInfo;
import dev.pluginguard.engine.model.ArtifactType;

import java.util.ArrayList;
import java.util.List;

/** Proxy (BungeeCord/Velocity) hot paths: per-connection event handlers. No server tick. */
public class ProxyHotPathModel implements HotPathModel {

    private static final String BUNGEE_HANDLER = "Lnet/md_5/bungee/event/EventHandler;";
    private static final String VELOCITY_SUBSCRIBE = "Lcom/velocitypowered/api/event/Subscribe;";

    @Override
    public boolean supports(ArtifactType t) {
        return t == ArtifactType.PLUGIN_BUNGEE || t == ArtifactType.PLUGIN_VELOCITY;
    }

    @Override
    public List<HotEntrypoint> entrypoints(List<ClassScan> classes) {
        List<HotEntrypoint> out = new ArrayList<>();
        for (ClassScan c : classes) {
            for (MethodInfo m : c.methods()) {
                if (m.annotations().contains(BUNGEE_HANDLER) || m.annotations().contains(VELOCITY_SUBSCRIBE)) {
                    out.add(new HotEntrypoint(c.internalName(), m.name(), Heat.WARM));
                }
            }
        }
        return out;
    }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd analyzer && ./gradlew test --tests "dev.pluginguard.engine.perf.OtherHotPathModelsTest"`
Expected: PASS (4 tests).

- [ ] **Step 5: Run the full analyzer suite**

Run: `cd analyzer && ./gradlew test`
Expected: PASS (everything green).

- [ ] **Step 6: Commit**

```bash
git add analyzer/src/main/java/dev/pluginguard/engine/perf/ForgeHotPathModel.java \
        analyzer/src/main/java/dev/pluginguard/engine/perf/FabricHotPathModel.java \
        analyzer/src/main/java/dev/pluginguard/engine/perf/ProxyHotPathModel.java \
        analyzer/src/test/java/dev/pluginguard/engine/perf/OtherHotPathModelsTest.java
git commit -m "feat(perf): Forge/Fabric/Proxy hot-path models"
```

---

## Task 12: Web type contract (`types.ts`)

**Files:**
- Modify: `web/lib/types.ts`

**Interfaces:**
- Produces TS mirrors: `Axis`, `AxisScore`, `RecommendationLevel`, `Recommendation`, `"PERFORMANCE"` in `Category`, and `axes` + `recommendation` on `ScanResult`.

- [ ] **Step 1: Add the new types**

In `web/lib/types.ts`, add `"PERFORMANCE"` to the `Category` union, and add these declarations + fields:

```ts
export type Axis = "SECURITY" | "PERFORMANCE" | "COMPATIBILITY" | "HEALTH" | "LICENSE";

export type RecommendationLevel =
  | "SAFE_TO_INSTALL"
  | "INSTALL_WITH_CARE"
  | "RISKY"
  | "AVOID"
  | "DO_NOT_INSTALL";

export interface AxisScore {
  axis: Axis;
  score: number;
  verdict: Verdict;
  counts: SeverityCounts;
  headline: string;
}

export interface Recommendation {
  level: RecommendationLevel;
  headline: string;
  perAxis: string[];
}
```

Add to the `Category` union (after `"DATA_PACK"` / before `"PROVENANCE"`): `| "PERFORMANCE"`.

Add to the `ScanResult` interface (after `sandbox`):

```ts
  axes: AxisScore[];
  recommendation: Recommendation;
```

- [ ] **Step 2: Type-check**

Run: `cd web && npx tsc --noEmit`
Expected: No errors from `types.ts` (downstream components updated in later tasks may still error — that's expected until Tasks 13–15).

- [ ] **Step 3: Commit**

```bash
git add web/lib/types.ts
git commit -m "feat(web): types for axes + recommendation contract"
```

---

## Task 13: Web labels, colors and icon (`format.ts`, `icons.tsx`)

**Files:**
- Modify: `web/lib/format.ts`
- Modify: `web/components/icons.tsx`

**Interfaces:**
- Produces: `CATEGORY_LABEL.PERFORMANCE`, `AXIS_LABEL`, `RECOMMENDATION_LABEL`, `recommendationColor(level)`, and a `BoltIcon` (perf/lightning).

- [ ] **Step 1: Add the perf category label + axis/recommendation helpers to `format.ts`**

Add `PERFORMANCE: "Performance"` to the `CATEGORY_LABEL` record. Then append:

```ts
import type { Axis, RecommendationLevel } from "./types";

export const AXIS_LABEL: Record<Axis, string> = {
  SECURITY: "Security",
  PERFORMANCE: "Performance",
  COMPATIBILITY: "Compatibility",
  HEALTH: "Code health",
  LICENSE: "Legal / license",
};

export const RECOMMENDATION_LABEL: Record<RecommendationLevel, string> = {
  SAFE_TO_INSTALL: "Safe to install",
  INSTALL_WITH_CARE: "Install with care",
  RISKY: "Risky",
  AVOID: "Avoid",
  DO_NOT_INSTALL: "Do not install",
};

/** Tailwind text colour for the overall recommendation banner. */
export function recommendationColor(level: RecommendationLevel): string {
  switch (level) {
    case "SAFE_TO_INSTALL":
      return "text-primary";
    case "INSTALL_WITH_CARE":
      return "text-info";
    case "RISKY":
      return "text-warning";
    case "AVOID":
    case "DO_NOT_INSTALL":
      return "text-danger";
  }
}
```

> NOTE: merge the `import type { Axis, RecommendationLevel } from "./types";` into the existing top-of-file `import type { ... } from "./types";` line rather than adding a duplicate import.

- [ ] **Step 2: Add a `BoltIcon` to `icons.tsx`**

Append to `web/components/icons.tsx`:

```tsx
export function BoltIcon(props: IconProps) {
  return (
    <svg {...base} {...props}>
      <path d="M13 3L5 13h6l-1 8 8-10h-6z" />
    </svg>
  );
}
```

- [ ] **Step 3: Type-check**

Run: `cd web && npx tsc --noEmit`
Expected: `format.ts` and `icons.tsx` clean.

- [ ] **Step 4: Commit**

```bash
git add web/lib/format.ts web/components/icons.tsx
git commit -m "feat(web): performance label, axis/recommendation labels + bolt icon"
```

---

## Task 14: Parameterize `ScoreGauge` and add `AxisScores`

**Files:**
- Modify: `web/components/ScoreGauge.tsx`
- Create: `web/components/AxisScores.tsx`

**Interfaces:**
- `ScoreGauge` gains an optional `label?: string` prop (defaults to `"safety / 100"`); existing call sites keep working.
- `AxisScores({ axes }: { axes: AxisScore[] })` renders a compact horizontal strip of axis meters.

> Re-read `web/components/ScoreGauge.tsx` first — it has uncommitted WIP. Make the minimal additive change (a new optional prop), do not rewrite it.

- [ ] **Step 1: Add an optional `label` prop to `ScoreGauge`**

Change the component signature and the label span:

```tsx
export function ScoreGauge({ score, label = "safety / 100" }: { score: number; label?: string }) {
```

and replace the hard-coded label:

```tsx
        <span className="micro-label mt-1 text-faint">{label}</span>
```

- [ ] **Step 2: Create `AxisScores`**

```tsx
// web/components/AxisScores.tsx
import type { AxisScore } from "@/lib/types";
import { AXIS_LABEL, verdictColor, scoreStroke } from "@/lib/format";

/** Compact horizontal strip of per-axis meters shown beside the main gauge. */
export function AxisScores({ axes }: { axes: AxisScore[] }) {
  if (!axes || axes.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-3">
      {axes.map((a) => (
        <div
          key={a.axis}
          className="flex min-w-[9rem] flex-1 flex-col gap-1 rounded-md border border-line bg-panel/40 p-3"
        >
          <span className="micro-label text-faint">{AXIS_LABEL[a.axis]}</span>
          <div className="flex items-baseline justify-between">
            <span
              className="font-display text-2xl font-semibold tabular-nums"
              style={{ color: scoreStroke(a.score) }}
            >
              {a.score}
            </span>
            <span className={`text-xs ${verdictColor(a.verdict)}`}>{a.verdict.replace("_", " ")}</span>
          </div>
          <div className="h-1 w-full overflow-hidden rounded-full bg-line">
            <div
              className="h-full rounded-full"
              style={{ width: `${a.score}%`, backgroundColor: scoreStroke(a.score) }}
            />
          </div>
          <span className="text-[11px] text-muted">{a.headline}</span>
        </div>
      ))}
    </div>
  );
}
```

- [ ] **Step 3: Type-check**

Run: `cd web && npx tsc --noEmit`
Expected: both files clean.

- [ ] **Step 4: Commit**

```bash
git add web/components/ScoreGauge.tsx web/components/AxisScores.tsx
git commit -m "feat(web): parameterize ScoreGauge label + AxisScores strip"
```

---

## Task 15: Recommendation banner + axis strip in `ReportView`

**Files:**
- Modify: `web/components/ReportView.tsx`

**Interfaces:**
- Consumes: `result.axes`, `result.recommendation`, `AxisScores`, `RECOMMENDATION_LABEL`, `recommendationColor`.

> Re-read `web/components/ReportView.tsx` (≈400 lines) to find the existing score/verdict header block before editing. The exact insertion lines depend on current content; place the banner + strip directly under the main score gauge/header.

- [ ] **Step 1: Import the new pieces**

At the top of `ReportView.tsx`, add:

```tsx
import { AxisScores } from "@/components/AxisScores";
import { RECOMMENDATION_LABEL, recommendationColor } from "@/lib/format";
```

(Merge with existing `@/lib/format` import if present.)

- [ ] **Step 2: Render the banner + strip under the score header**

Immediately after the existing main score/gauge header element, insert:

```tsx
{result.recommendation && (
  <div className="mt-4 rounded-md border border-line bg-panel/40 p-4">
    <div className="flex items-center gap-2">
      <span className="micro-label text-faint">Recommendation</span>
      <span className={`font-display text-lg font-semibold ${recommendationColor(result.recommendation.level)}`}>
        {RECOMMENDATION_LABEL[result.recommendation.level]}
      </span>
    </div>
    <p className="mt-1 text-sm text-muted">{result.recommendation.headline}</p>
  </div>
)}
{result.axes && result.axes.length > 0 && (
  <div className="mt-4">
    <AxisScores axes={result.axes} />
  </div>
)}
```

- [ ] **Step 3: Build the web app**

Run: `cd web && npm run build`
Expected: build succeeds (Next.js compiles; no type errors).

- [ ] **Step 4: Manual smoke check (optional but recommended)**

Run the analyzer and web (`cd analyzer && ./gradlew bootRun`; `cd web && npm run dev`), open `http://localhost:3000`, click **Demo report**, and confirm the recommendation banner + the Security/Performance axis meters render.

- [ ] **Step 5: Commit**

```bash
git add web/components/ReportView.tsx
git commit -m "feat(web): recommendation banner + axis strip in the report view"
```

---

## Task 16: Docs — README + PLAN (Phase 5)

**Files:**
- Modify: `README.md`
- Modify: `PLAN.md`

- [ ] **Step 1: Add a "Performance / lag risk" row + multi-axis note to `README.md`**

In the "What it checks" table, add a row:

```
| **Performance (lag risk)** | Static prediction of TPS impact: blocking I/O (JDBC/HTTP/file), `Thread.sleep`, sync chunk loads and other heavy work reachable from hot paths (event handlers, repeating sync tasks) — scored as its own axis, never mixed into the security score |
```

And add a short paragraph under the intro explaining the multi-axis report and the honest caveat (static perf analysis predicts *risk of lag*, not measured TPS; can't see real load/data sizes or runtime async; deep call-graph findings carry lower confidence).

- [ ] **Step 2: Add a "Phase 5" section to `PLAN.md`**

Append a `## Phase 5 — Многоосевой fitness-отчёт + Performance (сделано)` section summarizing: the `Axis` model, per-axis scoring, the install recommendation with security veto, and the Performance analyzer (Hybrid-C hot-path reachability across Bukkit/Forge/Fabric/proxy + data-pack lag re-route), with the honest framing.

- [ ] **Step 3: Commit**

```bash
git add README.md PLAN.md
git commit -m "docs: document multi-axis report + performance (lag-risk) analysis"
```

---

## Task 17: Full verification pass

- [ ] **Step 1: Run the entire analyzer test suite**

Run: `cd analyzer && ./gradlew test`
Expected: BUILD SUCCESSFUL — all suites green, including the pre-existing security regressions (unchanged), the new foundation/scoring/recommendation tests, and all perf tests.

- [ ] **Step 2: Build the web app**

Run: `cd web && npm run build`
Expected: build succeeds.

- [ ] **Step 3: Confirm the API contract end-to-end (optional)**

Run the analyzer, then `curl -s http://localhost:8080/api/demo | python -m json.tool` and confirm the JSON contains `axes` (with `SECURITY` and `PERFORMANCE`) and `recommendation`.

- [ ] **Step 4: Final commit (if any docs/cleanups remain)**

```bash
git add -A
git commit -m "chore: finalize multi-axis + performance analysis sub-project"
```

---

## Self-Review (completed by plan author)

**1. Spec coverage:**
- Foundation `Axis`/`Category.axis()` → Task 1. `AxisScore`/per-axis scoring → Task 2. `Recommendation`/veto → Task 3. `ScanResult`+engine wiring+version bump+DemoData → Task 4. ✓
- Annotation capture engine extension → Task 6 (with JarBuilder support in Task 5). ✓
- Hot-path models (Bukkit/Forge/Fabric/Proxy) → Tasks 8, 11. Data-pack re-route → Task 10. ✓
- Call-graph reachability + cold-path suppression + recursion → Task 9. ✓
- Perf sink table + severity formula → Tasks 7, 10. ✓
- Web (types, labels/icon, gauge/AxisScores, ReportView) → Tasks 12–15. ✓
- Tests (foundation regression, hot-path, reachability, sinks, async control, datapack) → distributed across Tasks 1–11. ✓
- Honest framing + docs → Task 16. ✓

**2. Placeholder scan:** No "TBD"/"implement later"/"add error handling"; every code step shows complete code. The only forward-reference (Task 10 → Forge/Fabric/Proxy) is resolved by creating compiling stubs in Task 10 Step 4, fleshed out in Task 11. ✓

**3. Type consistency:** `Axis`, `AxisScore(axis,score,verdict,counts,headline)`, `Recommendation(level,headline,perAxis)`, `RecommendationLevel`, `Heat{HOT,WARM,COOL}`, `HotEntrypoint(classInternalName,methodName,heat)`, `HotPathModel.{supports,entrypoints}`, `CallGraph.{key,reachableFrom,Reach(heat,distance)}`, `PerfSinkTable.{match,PerfSink,SinkWeight}`, `MethodInfo.annotations()`, `ScanResult` trailing `axes`/`recommendation` — names used identically across producing and consuming tasks. ✓

**Known intentional behavior change:** top-level `ScanResult.score`/`verdict` now derive from the SECURITY axis (security findings only) rather than all findings. With only security findings present (all existing tests), the value is identical, so regressions stay green; once PERFORMANCE findings exist they no longer drag down the security number — which is the intended design.
