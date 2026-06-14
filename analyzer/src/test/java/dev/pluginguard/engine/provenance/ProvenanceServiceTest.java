package dev.pluginguard.engine.provenance;

import dev.pluginguard.api.InMemoryScanStore;
import dev.pluginguard.api.ScanStore;
import dev.pluginguard.config.AnalyzerProperties;
import dev.pluginguard.engine.model.ArtifactType;
import dev.pluginguard.engine.model.ClassDiff;
import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.PluginInfo;
import dev.pluginguard.engine.model.ProvenanceMatch;
import dev.pluginguard.engine.model.ProvenanceReport;
import dev.pluginguard.engine.model.ProvenanceStatus;
import dev.pluginguard.engine.model.ScanResult;
import dev.pluginguard.engine.model.SeverityCounts;
import dev.pluginguard.engine.model.Summaries;
import dev.pluginguard.engine.model.Verdict;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link ProvenanceService}: verdict flooring, the synchronous short-circuits
 * (disabled / unentitled / no-identity) and the async store update, using a stubbed verifier.
 */
class ProvenanceServiceTest {

    // ---- verdict flooring ------------------------------------------------------------------

    @Test
    void tamperedWithInjectedClassesFloorsToCritical() {
        assertThat(ProvenanceService.floorVerdict(Verdict.LOW_RISK, tampered(true)))
                .isEqualTo(Verdict.CRITICAL_RISK);
    }

    @Test
    void tamperedWithoutInjectedClassesFloorsToHigh() {
        assertThat(ProvenanceService.floorVerdict(Verdict.MINIMAL_RISK, tampered(false)))
                .isEqualTo(Verdict.HIGH_RISK);
    }

    @Test
    void tamperedNeverLowersAWorseVerdict() {
        assertThat(ProvenanceService.floorVerdict(Verdict.CRITICAL_RISK, tampered(false)))
                .isEqualTo(Verdict.CRITICAL_RISK);
    }

    @Test
    void verifiedDoesNotChangeTheVerdict() {
        ProvenanceReport verified = report(ProvenanceStatus.VERIFIED, null, "ok");
        assertThat(ProvenanceService.floorVerdict(Verdict.LOW_RISK, verified)).isEqualTo(Verdict.LOW_RISK);
    }

    // ---- synchronous short-circuits --------------------------------------------------------

    @Test
    void disabledByDefaultAttachesDisabledStatus() {
        ProvenanceService service = service(new AnalyzerProperties(), report(ProvenanceStatus.VERIFIED, null, "x"));
        ScanResult after = service.attach(result("X", "1.0"), new byte[]{1});
        assertThat(after.provenance().status()).isEqualTo(ProvenanceStatus.DISABLED);
    }

    @Test
    void unentitledCallerIsSkipped() {
        ProvenanceService service = service(enabled(), report(ProvenanceStatus.VERIFIED, null, "x"));
        ScanResult after = service.attach(result("X", "1.0"), new byte[]{1}, false);
        assertThat(after.provenance().status()).isEqualTo(ProvenanceStatus.SKIPPED);
        assertThat(after.provenance().note()).contains("Pro");
    }

    @Test
    void noIdentityIsUnverifiedAndNeverRuns() {
        ProvenanceService service = service(enabled(), report(ProvenanceStatus.VERIFIED, null, "x"));
        ScanResult after = service.attach(result(null, null), new byte[]{1});
        assertThat(after.provenance().status()).isEqualTo(ProvenanceStatus.UNVERIFIED);
    }

    // ---- async store update ----------------------------------------------------------------

    @Test
    void enabledRunsAsynchronouslyAndFloorsTheStoredVerdict() throws Exception {
        ScanStore store = new InMemoryScanStore();
        ProvenanceService service = new ProvenanceService(enabled(),
                stubVerifier(enabled(), tampered(true)), store);

        ScanResult pending = service.attach(result("X", "1.0"), new byte[]{1});
        assertThat(pending.provenance().status()).isEqualTo(ProvenanceStatus.PENDING);
        store.put(pending);

        ProvenanceStatus finalStatus = awaitFinal(store, pending.id());
        assertThat(finalStatus).isEqualTo(ProvenanceStatus.TAMPERED);
        assertThat(store.get(pending.id()).orElseThrow().verdict()).isEqualTo(Verdict.CRITICAL_RISK);
    }

    // ---- helpers ---------------------------------------------------------------------------

    private static ProvenanceStatus awaitFinal(ScanStore store, String id) throws InterruptedException {
        for (int i = 0; i < 100; i++) {
            ProvenanceStatus s = store.get(id).map(r -> r.provenance().status()).orElse(null);
            if (s != null && s != ProvenanceStatus.PENDING && s != ProvenanceStatus.RUNNING) {
                return s;
            }
            Thread.sleep(20);
        }
        return store.get(id).map(r -> r.provenance().status()).orElse(null);
    }

    private static AnalyzerProperties enabled() {
        AnalyzerProperties p = new AnalyzerProperties();
        p.getProvenance().setEnabled(true);
        return p;
    }

    private static ProvenanceService service(AnalyzerProperties props, ProvenanceReport canned) {
        return new ProvenanceService(props, stubVerifier(props, canned), new InMemoryScanStore());
    }

    private static ProvenanceVerifier stubVerifier(AnalyzerProperties props, ProvenanceReport canned) {
        return new ProvenanceVerifier(props, null, null, List.of()) {
            @Override
            public ProvenanceReport verify(ScanResult result, byte[] jarBytes) {
                return canned;
            }
        };
    }

    private static ProvenanceReport tampered(boolean injected) {
        ClassDiff diff = injected
                ? new ClassDiff(2, 3, List.of("evil.Backdoor"), List.of(), List.of(), false)
                : null;
        ProvenanceMatch match = new ProvenanceMatch("Modrinth", "X", "url", "1.0", "X.jar", "h", null, false);
        return report(ProvenanceStatus.TAMPERED, match, "tampered", diff);
    }

    private static ProvenanceReport report(ProvenanceStatus status, ProvenanceMatch match, String note) {
        return report(status, match, note, null);
    }

    private static ProvenanceReport report(ProvenanceStatus status, ProvenanceMatch match,
                                           String note, ClassDiff diff) {
        Instant t = Instant.parse("2026-06-09T12:00:00Z");
        return new ProvenanceReport(status, t, t, 1L, "X", "1.0", match, diff,
                List.of("Modrinth"), List.of(), note);
    }

    private static ScanResult result(String name, String version) {
        PluginInfo info = name == null ? null
                : new PluginInfo("plugin.yml", name, version, "com.example.Main", "1.21",
                List.of(), List.of(), List.of(), List.of(), List.of(), List.of());
        List<Finding> findings = List.of();
        SeverityCounts counts = SeverityCounts.from(findings);
        Summaries summaries = new Summaries(List.of(), List.of(), List.of(), 1, 1);
        return new ScanResult("id-1", "upload.jar", "sha", 100L, "Paper", ArtifactType.PLUGIN_BUKKIT,
                info != null ? info.main() : null, "1.21", 80, Verdict.LOW_RISK, 0, counts, info,
                findings, summaries, List.of(), Instant.parse("2026-06-09T12:00:00Z"), 5L, "0.1.0",
                null, null);
    }
}
