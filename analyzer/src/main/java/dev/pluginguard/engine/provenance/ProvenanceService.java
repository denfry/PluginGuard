package dev.pluginguard.engine.provenance;

import dev.pluginguard.api.ScanStore;
import dev.pluginguard.config.AnalyzerProperties;
import dev.pluginguard.engine.model.ProvenanceReport;
import dev.pluginguard.engine.model.ProvenanceStatus;
import dev.pluginguard.engine.model.ScanResult;
import dev.pluginguard.engine.model.Verdict;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Orchestrates the optional online authenticity verification. Like {@link dev.pluginguard.engine.sandbox.SandboxService},
 * the static report is returned immediately and the (network-bound, possibly slow) verification runs
 * asynchronously, updating the stored report in place so {@code GET /api/scan/{id}} reflects
 * PENDING → RUNNING → VERIFIED/TAMPERED/NOT_FOUND. {@code TAMPERED} floors the verdict, since a
 * modified copy of a known plugin is strong evidence of risk; {@code VERIFIED} stays informational.
 */
@Service
public class ProvenanceService {

    private static final Logger log = LoggerFactory.getLogger(ProvenanceService.class);

    private final AnalyzerProperties.Provenance cfg;
    private final ProvenanceVerifier verifier;
    private final ScanStore store;
    private final ExecutorService executor = Executors.newFixedThreadPool(2, r -> {
        Thread t = new Thread(r, "provenance-worker");
        t.setDaemon(true);
        return t;
    });

    public ProvenanceService(AnalyzerProperties properties, ProvenanceVerifier verifier, ScanStore store) {
        this.cfg = properties.getProvenance();
        this.verifier = verifier;
        this.store = store;
    }

    /** Entitled by default — preserves behavior for callers without a plan (default profile). */
    public ScanResult attach(ScanResult result, byte[] jarBytes) {
        return attach(result, jarBytes, true);
    }

    /**
     * Attaches the initial provenance section and, if warranted, launches the async verification.
     * Returns immediately.
     *
     * @param entitled whether the caller's plan includes online verification (a paid feature when an
     *                 API layer is present); {@code false} skips the run.
     */
    public ScanResult attach(ScanResult result, byte[] jarBytes, boolean entitled) {
        if (!cfg.isEnabled()) {
            return result.withProvenance(
                    ProvenanceReport.of(ProvenanceStatus.DISABLED,
                            "Online authenticity verification is disabled.", List.of()),
                    result.verdict(), result.notes());
        }
        if (!entitled) {
            return result.withProvenance(
                    ProvenanceReport.of(ProvenanceStatus.SKIPPED,
                            "Online verification is available on the Pro and Business plans.",
                            ProvenanceVerifier.caveats()),
                    result.verdict(), result.notes());
        }
        if (Identity.from(result).isEmpty()) {
            return result.withProvenance(
                    ProvenanceReport.of(ProvenanceStatus.UNVERIFIED,
                            "No plugin name/version or source link was found to verify against.",
                            ProvenanceVerifier.caveats()),
                    result.verdict(), result.notes());
        }
        ScanResult pending = result.withProvenance(
                ProvenanceReport.of(ProvenanceStatus.PENDING, "Online verification queued.",
                        ProvenanceVerifier.caveats()),
                result.verdict(), result.notes());
        launchAsync(pending, jarBytes);
        return pending;
    }

    private void launchAsync(ScanResult pending, byte[] jarBytes) {
        String id = pending.id();
        executor.submit(() -> {
            try {
                // Verify off the store lock; apply only the provenance section onto the latest value
                // so a concurrent sandbox update is never clobbered (and vice versa).
                store.update(id, this::markRunning);
                ProvenanceReport report = verifier.verify(pending, jarBytes);
                store.update(id, prev -> foldInto(prev, report));
            } catch (RuntimeException e) {
                log.warn("Provenance job {} crashed: {}", id, e.toString());
                store.update(id, prev -> prev.withProvenance(
                        ProvenanceReport.of(ProvenanceStatus.FAILED,
                                "Verification crashed: " + e.getMessage(), ProvenanceVerifier.caveats()),
                        prev.verdict(), prev.notes()));
            }
        });
    }

    private ScanResult markRunning(ScanResult prev) {
        return prev.withProvenance(
                ProvenanceReport.of(ProvenanceStatus.RUNNING, "Checking official sources…",
                        ProvenanceVerifier.caveats()),
                prev.verdict(), prev.notes());
    }

    /** Folds a finished verification onto a base report, raising (never lowering) its verdict. */
    static ScanResult foldInto(ScanResult base, ProvenanceReport report) {
        Verdict verdict = floorVerdict(base.verdict(), report);
        List<String> notes = withProvenanceNote(base.notes(), report, verdict, base.verdict());
        return base.withProvenance(report, verdict, notes);
    }

    /** A tampered copy of a known plugin floors the verdict; injected classes make it critical. */
    static Verdict floorVerdict(Verdict staticVerdict, ProvenanceReport report) {
        if (report.status() != ProvenanceStatus.TAMPERED) {
            return staticVerdict;
        }
        Verdict floor = report.diff() != null && !report.diff().addedClasses().isEmpty()
                ? Verdict.CRITICAL_RISK
                : Verdict.HIGH_RISK;
        return floor.ordinal() > staticVerdict.ordinal() ? floor : staticVerdict;
    }

    private static List<String> withProvenanceNote(List<String> notes, ProvenanceReport report,
                                                   Verdict newVerdict, Verdict oldVerdict) {
        List<String> out = new ArrayList<>(notes);
        switch (report.status()) {
            case VERIFIED -> out.add("Authenticity verified: matches the official release"
                    + (report.match() != null ? " on " + report.match().source() : "") + ".");
            case TAMPERED -> {
                out.add("Authenticity check: this file does NOT match the official release.");
                if (newVerdict != oldVerdict) {
                    out.add("Verdict raised to " + newVerdict.getLabel() + " by online tamper evidence.");
                }
            }
            case NOT_FOUND -> out.add("Authenticity could not be verified: not found on any official source.");
            case FAILED -> {
                if (report.note() != null) {
                    out.add("Online verification: " + report.note());
                }
            }
            default -> { /* PENDING/RUNNING/UNVERIFIED/SKIPPED/DISABLED add no note */ }
        }
        return out;
    }

    @PreDestroy
    void shutdown() {
        executor.shutdownNow();
    }
}
