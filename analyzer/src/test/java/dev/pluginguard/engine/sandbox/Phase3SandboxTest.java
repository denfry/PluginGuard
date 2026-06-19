package dev.pluginguard.engine.sandbox;

import dev.pluginguard.api.ScanStore;
import dev.pluginguard.config.AnalyzerProperties;
import dev.pluginguard.engine.AnalysisEngine;
import dev.pluginguard.engine.model.ArtifactType;
import dev.pluginguard.engine.model.BehaviorEvent;
import dev.pluginguard.engine.model.Category;
import dev.pluginguard.engine.model.DynamicFinding;
import dev.pluginguard.engine.model.DynamicFinding.DynamicCorrelation;
import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.PluginInfo;
import dev.pluginguard.engine.model.SandboxReport;
import dev.pluginguard.engine.model.SandboxStatus;
import dev.pluginguard.engine.model.ScanResult;
import dev.pluginguard.engine.model.Severity;
import dev.pluginguard.engine.model.SeverityCounts;
import dev.pluginguard.engine.model.Summaries;
import dev.pluginguard.engine.model.Verdict;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Phase&nbsp;3 dynamic-sandbox tests. They exercise everything that does <em>not</em> need a Docker
 * daemon — the hardened command construction, behavior-log parsing, dynamic-finding mapping +
 * static correlation, verdict flooring, and the async orchestration — using a stubbed runner with
 * canned behavior, so the suite stays deterministic and offline-safe.
 */
class Phase3SandboxTest {

    // ---- 3.1 hardened docker command -------------------------------------------------------

    @Test
    void dockerCommandIsHardened() {
        AnalyzerProperties.Sandbox cfg = new AnalyzerProperties().getSandbox();
        List<String> cmd = DockerSandboxRunner.buildDockerCommand(
                cfg, java.nio.file.Path.of("work", "in"), java.nio.file.Path.of("work", "out"),
                "com.example.Main", List.of("demo"));

        assertThat(cmd).containsSequence("--network", "none");
        assertThat(cmd).contains("--read-only");
        assertThat(cmd).containsSequence("--cap-drop", "ALL");
        assertThat(cmd).containsSequence("--security-opt", "no-new-privileges");
        assertThat(cmd).containsSequence("-u", "65534:65534");
        assertThat(cmd).containsSequence("--pids-limit", "128");
        assertThat(cmd).contains("--rm", "--memory", "256m");
        assertThat(cmd).contains("-javaagent:/in/runtime.jar", "/in/plugin.jar", "/out/behavior.jsonl");
        assertThat(cmd).contains("-Djava.security.manager=allow");
        // The plugin main class and its commands are passed to the harness.
        assertThat(cmd).containsSubsequence("/out/behavior.jsonl", "com.example.Main", "demo");
        // Read-only input mount, writable output mount.
        assertThat(cmd).anyMatch(s -> s.endsWith(":/in:ro"));
        assertThat(cmd).anyMatch(s -> s.endsWith(":/out"));
    }

    // ---- behavior-log parsing --------------------------------------------------------------

    @Test
    void parsesJsonLinesAndSkipsGarbage() {
        String jsonl = """
                {"type":"LIFECYCLE","target":"onEnable","detail":null,"source":null,"blocked":false}
                not json
                {"type":"PROCESS_EXEC","target":"/bin/sh -c curl evil","detail":"x","source":null,"blocked":true}

                {"missing":"type"}
                """;
        List<BehaviorEvent> events = new BehaviorLogParser().parse(jsonl);
        assertThat(events).hasSize(2);
        assertThat(events.get(1).type()).isEqualTo("PROCESS_EXEC");
        assertThat(events.get(1).blocked()).isTrue();
        assertThat(events.get(1).target()).contains("curl evil");
    }

    // ---- dynamic-finding mapping + correlation ---------------------------------------------

    @Test
    void mapsBehaviorToDynamicFindingsWithCorrelation() {
        // Static findings include a NETWORK signal but NOT a PROCESS one.
        List<Finding> staticFindings = List.of(
                Finding.builder("IOC_URL", Category.NETWORK, Severity.LOW).title("net").build());

        List<BehaviorEvent> events = List.of(
                new BehaviorEvent("PROCESS_EXEC", "/bin/sh", "blocked", null, true),
                new BehaviorEvent("PROCESS_EXEC", "/bin/sh", "blocked", null, true), // repeat → occurrences
                new BehaviorEvent("NETWORK_CONNECT", "evil.com:443", null, null, true),
                new BehaviorEvent("LIFECYCLE", "onEnable", null, null, false)); // not a finding

        DynamicFindingMapper mapper = new DynamicFindingMapper();
        List<DynamicFinding> findings = mapper.map(events, staticFindings);

        // PROCESS_EXEC (CRITICAL) first, NETWORK_CONNECT (HIGH) second; LIFECYCLE dropped.
        assertThat(findings).hasSize(2);
        DynamicFinding exec = findings.get(0);
        assertThat(exec.eventType()).isEqualTo("PROCESS_EXEC");
        assertThat(exec.severity()).isEqualTo(Severity.CRITICAL);
        assertThat(exec.occurrences()).isEqualTo(2);
        assertThat(exec.blocked()).isTrue();
        // Static had no PROCESS finding → this is dynamic-only (more alarming).
        assertThat(exec.correlation()).isEqualTo(DynamicCorrelation.DYNAMIC_ONLY);

        DynamicFinding net = findings.get(1);
        assertThat(net.eventType()).isEqualTo("NETWORK_CONNECT");
        assertThat(net.correlation()).isEqualTo(DynamicCorrelation.CONFIRMS_STATIC);

        assertThat(mapper.worstSeverity(findings)).isEqualTo(Severity.CRITICAL);
        assertThat(mapper.caveats()).anyMatch(s -> s.contains("sandbox evasion"));
    }

    // ---- verdict flooring ------------------------------------------------------------------

    @Test
    void dynamicEvidenceFloorsVerdictButOnlyOnCompletion() {
        assertThat(SandboxService.floorVerdict(Verdict.LOW_RISK, Severity.CRITICAL, SandboxStatus.COMPLETED))
                .isEqualTo(Verdict.CRITICAL_RISK);
        assertThat(SandboxService.floorVerdict(Verdict.MINIMAL_RISK, Severity.HIGH, SandboxStatus.COMPLETED))
                .isEqualTo(Verdict.HIGH_RISK);
        // Never lowers a worse static verdict.
        assertThat(SandboxService.floorVerdict(Verdict.CRITICAL_RISK, Severity.MEDIUM, SandboxStatus.COMPLETED))
                .isEqualTo(Verdict.CRITICAL_RISK);
        // A failed/unavailable run does not change the verdict.
        assertThat(SandboxService.floorVerdict(Verdict.LOW_RISK, Severity.CRITICAL, SandboxStatus.FAILED))
                .isEqualTo(Verdict.LOW_RISK);
    }

    // ---- service: synchronous core ---------------------------------------------------------

    @Test
    void executeFoldsDynamicResultIntoReportAndFloorsVerdict() {
        SandboxOutcome canned = SandboxOutcome.completed(List.of(
                new BehaviorEvent("PROCESS_EXEC", "/bin/sh -c curl evil", "blocked", null, true)), null);
        SandboxService service = service(canned, new AnalyzerProperties());

        ScanResult result = sample("com.example.Main", Verdict.LOW_RISK, List.of());
        ScanResult after = service.execute(result, new byte[]{1, 2, 3});

        SandboxReport sb = after.sandbox();
        assertThat(sb.status()).isEqualTo(SandboxStatus.COMPLETED);
        assertThat(sb.runner()).isEqualTo("stub");
        assertThat(sb.behaviorEventCount()).isEqualTo(1);
        assertThat(sb.dynamicFindings()).hasSize(1);
        assertThat(sb.worstSeverity()).isEqualTo(Severity.CRITICAL);
        assertThat(after.verdict()).isEqualTo(Verdict.CRITICAL_RISK);
        assertThat(after.notes()).anyMatch(n -> n.contains("Verdict raised"));
    }

    // ---- service: disabled / skipped / async -----------------------------------------------

    @Test
    void disabledSandboxAttachesDisabledStatusAndDoesNotRun() {
        AnalyzerProperties props = new AnalyzerProperties(); // sandbox.enabled stays false
        SandboxService service = service(SandboxOutcome.completed(List.of(), null), props);

        ScanResult after = service.attach(sample("com.example.Main", Verdict.LOW_RISK, List.of()), new byte[0]);
        assertThat(after.sandbox().status()).isEqualTo(SandboxStatus.DISABLED);
    }

    @Test
    void enabledSandboxWithoutMainClassIsSkipped() {
        AnalyzerProperties props = enabledProps();
        SandboxService service = service(SandboxOutcome.completed(List.of(), null), props);

        ScanResult after = service.attach(sample(null, Verdict.LOW_RISK, List.of()), new byte[0]);
        assertThat(after.sandbox().status()).isEqualTo(SandboxStatus.SKIPPED);
    }

    @Test
    void enabledSandboxRunsAsynchronouslyAndUpdatesTheStore() throws Exception {
        AnalyzerProperties props = enabledProps();
        ScanStore store = new ScanStore();
        SandboxOutcome canned = SandboxOutcome.completed(List.of(
                new BehaviorEvent("NETWORK_CONNECT", "evil.com:443", null, null, true)), null);
        SandboxService service = new SandboxService(props, new StubRunner(canned), store);

        ScanResult pending = service.attach(sample("com.example.Main", Verdict.LOW_RISK, List.of()), new byte[]{9});
        assertThat(pending.sandbox().status()).isEqualTo(SandboxStatus.PENDING);
        store.put(pending);

        SandboxStatus finalStatus = awaitFinal(store, pending.id());
        assertThat(finalStatus).isEqualTo(SandboxStatus.COMPLETED);
        SandboxReport sb = store.get(pending.id()).orElseThrow().sandbox();
        assertThat(sb.dynamicFindings()).anyMatch(f -> f.eventType().equals("NETWORK_CONNECT"));
    }

    // ---- helpers ---------------------------------------------------------------------------

    private static SandboxStatus awaitFinal(ScanStore store, String id) throws InterruptedException {
        for (int i = 0; i < 100; i++) {
            SandboxStatus s = store.get(id).map(r -> r.sandbox().status()).orElse(null);
            if (s == SandboxStatus.COMPLETED || s == SandboxStatus.FAILED || s == SandboxStatus.UNAVAILABLE) {
                return s;
            }
            Thread.sleep(20);
        }
        return store.get(id).map(r -> r.sandbox().status()).orElse(null);
    }

    private static AnalyzerProperties enabledProps() {
        AnalyzerProperties props = new AnalyzerProperties();
        props.getSandbox().setEnabled(true);
        return props;
    }

    private static SandboxService service(SandboxOutcome outcome, AnalyzerProperties props) {
        return new SandboxService(props, new StubRunner(outcome), new ScanStore());
    }

    private static ScanResult sample(String mainClass, Verdict verdict, List<Finding> findings) {
        SeverityCounts counts = SeverityCounts.from(findings);
        PluginInfo info = new PluginInfo("plugin.yml", "Demo", "1.0", mainClass, "1.21",
                List.of(), List.of("demo"), List.of(), List.of(), List.of(), List.of());
        Summaries summaries = new Summaries(List.of(), List.of(), List.of(), 1, 1);
        return new ScanResult("id-1", "demo.jar", "abc", 100L, "Paper", ArtifactType.PLUGIN_BUKKIT,
                mainClass, "1.21", 80, verdict, 0, counts, info, findings, summaries, List.of(),
                Instant.parse("2026-06-09T12:00:00Z"), 5L, AnalysisEngine.ENGINE_VERSION, null,
                java.util.List.of(),
                new dev.pluginguard.engine.model.Recommendation(
                        dev.pluginguard.engine.model.RecommendationLevel.SAFE_TO_INSTALL, "test", java.util.List.of()));
    }

    private record StubRunner(SandboxOutcome outcome) implements SandboxRunner {
        @Override public String name() { return "stub"; }
        @Override public boolean isAvailable() { return true; }
        @Override public SandboxOutcome run(SandboxJob job) { return outcome; }
    }
}
