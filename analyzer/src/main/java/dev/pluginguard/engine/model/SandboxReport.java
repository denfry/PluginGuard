package dev.pluginguard.engine.model;

import java.time.Instant;
import java.util.List;

/**
 * The dynamic-analysis section of a {@link ScanResult}. Present whenever the sandbox feature is
 * enabled (even if the result is {@code DISABLED}/{@code UNAVAILABLE}), so the UI can always explain
 * what dynamic analysis did or did not happen. Part of the JSON API contract.
 *
 * @param status            where the sandbox job is in its lifecycle
 * @param runner            which runtime executed it (e.g. {@code docker}), or {@code null}
 * @param startedAt         when the run started, or {@code null} if it never ran
 * @param finishedAt        when the run finished, or {@code null}
 * @param durationMs        wall-clock duration of the run, or 0
 * @param worstSeverity     most severe dynamic finding, or {@code null} if none
 * @param behaviorEventCount total behavior events observed
 * @param dynamicFindings   aggregated dynamic findings, most severe first
 * @param behaviorEvents    the (capped) raw behavior trail for transparency
 * @param caveats           explicit honesty notes about what a sandbox can and cannot prove
 * @param note              a single status line (e.g. why it was skipped)
 */
public record SandboxReport(
        SandboxStatus status,
        String runner,
        Instant startedAt,
        Instant finishedAt,
        long durationMs,
        Severity worstSeverity,
        int behaviorEventCount,
        List<DynamicFinding> dynamicFindings,
        List<BehaviorEvent> behaviorEvents,
        List<String> caveats,
        String note) {

    /** A not-yet-run report in the given status (DISABLED / PENDING / UNAVAILABLE / SKIPPED). */
    public static SandboxReport of(SandboxStatus status, String note, List<String> caveats) {
        return new SandboxReport(status, null, null, null, 0, null, 0,
                List.of(), List.of(), caveats == null ? List.of() : caveats, note);
    }
}
