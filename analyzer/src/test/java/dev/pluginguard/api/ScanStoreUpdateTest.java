package dev.pluginguard.api;

import dev.pluginguard.engine.model.ArtifactType;
import dev.pluginguard.engine.model.ProvenanceReport;
import dev.pluginguard.engine.model.ProvenanceStatus;
import dev.pluginguard.engine.model.SandboxReport;
import dev.pluginguard.engine.model.SandboxStatus;
import dev.pluginguard.engine.model.ScanResult;
import dev.pluginguard.engine.model.SeverityCounts;
import dev.pluginguard.engine.model.Summaries;
import dev.pluginguard.engine.model.Verdict;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The two async writers (sandbox + provenance) update a stored report concurrently. These tests
 * confirm {@link ScanStore#update} applies only its own section and never clobbers the other's.
 */
class ScanStoreUpdateTest {

    @Test
    void eachUpdateAppliesOnlyItsSection() {
        ScanStore store = new InMemoryScanStore();
        ScanResult base = base("id-1");
        store.put(base);

        store.update("id-1", prev -> prev.withSandbox(
                SandboxReport.of(SandboxStatus.COMPLETED, "done", List.of()),
                prev.verdict(), prev.notes()));
        store.update("id-1", prev -> prev.withProvenance(
                ProvenanceReport.of(ProvenanceStatus.VERIFIED, "authentic", List.of()),
                prev.verdict(), prev.notes()));

        ScanResult stored = store.get("id-1").orElseThrow();
        assertThat(stored.sandbox().status()).isEqualTo(SandboxStatus.COMPLETED);
        assertThat(stored.provenance().status()).isEqualTo(ProvenanceStatus.VERIFIED);
    }

    @Test
    void updateOfMissingIdReturnsNull() {
        ScanStore store = new InMemoryScanStore();
        assertThat(store.update("nope", prev -> prev)).isNull();
    }

    @Test
    void concurrentSectionUpdatesBothSurvive() throws Exception {
        ScanStore store = new InMemoryScanStore();
        store.put(base("id-1"));

        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(2);
        Runnable sandbox = () -> {
            await(start);
            store.update("id-1", prev -> prev.withSandbox(
                    SandboxReport.of(SandboxStatus.COMPLETED, "done", List.of()),
                    prev.verdict(), prev.notes()));
            done.countDown();
        };
        Runnable provenance = () -> {
            await(start);
            store.update("id-1", prev -> prev.withProvenance(
                    ProvenanceReport.of(ProvenanceStatus.TAMPERED, "modified", List.of()),
                    prev.verdict(), prev.notes()));
            done.countDown();
        };
        new Thread(sandbox).start();
        new Thread(provenance).start();
        start.countDown();
        assertThat(done.await(5, TimeUnit.SECONDS)).isTrue();

        ScanResult stored = store.get("id-1").orElseThrow();
        assertThat(stored.sandbox()).isNotNull();
        assertThat(stored.provenance()).isNotNull();
        assertThat(stored.sandbox().status()).isEqualTo(SandboxStatus.COMPLETED);
        assertThat(stored.provenance().status()).isEqualTo(ProvenanceStatus.TAMPERED);
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static ScanResult base(String id) {
        SeverityCounts counts = SeverityCounts.from(List.of());
        Summaries summaries = new Summaries(List.of(), List.of(), List.of(), 1, 1);
        return new ScanResult(id, "upload.jar", "sha", 100L, "Paper", ArtifactType.PLUGIN_BUKKIT,
                "com.example.Main", "1.21", 80, Verdict.LOW_RISK, 0, counts, null, List.of(),
                summaries, List.of(), Instant.parse("2026-06-09T12:00:00Z"), 5L, "0.1.0", null, null);
    }
}
