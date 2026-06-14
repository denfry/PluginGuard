package dev.pluginguard.engine.model;

import java.time.Instant;
import java.util.List;

/**
 * The online-authenticity section of a {@link ScanResult}. Present whenever the online-verification
 * feature is enabled (even if the result is {@code DISABLED}/{@code SKIPPED}), so the UI can always
 * explain what verification did or did not happen. Part of the JSON API contract.
 *
 * @param status         the verification lifecycle / outcome
 * @param startedAt      when verification started, or {@code null} if it never ran
 * @param finishedAt     when verification finished, or {@code null}
 * @param durationMs     wall-clock duration of the verification, or 0
 * @param pluginName     the plugin name that was looked up, or {@code null}
 * @param pluginVersion  the plugin version that was looked up, or {@code null}
 * @param match          the official release compared against, or {@code null} when none was found
 * @param diff           class-level diff vs. the official release (only for {@code TAMPERED}), or {@code null}
 * @param sourcesQueried which official sources were consulted (for transparency)
 * @param caveats        explicit honesty notes about what verification can and cannot prove
 * @param note           a single status line (e.g. why it was skipped)
 */
public record ProvenanceReport(
        ProvenanceStatus status,
        Instant startedAt,
        Instant finishedAt,
        long durationMs,
        String pluginName,
        String pluginVersion,
        ProvenanceMatch match,
        ClassDiff diff,
        List<String> sourcesQueried,
        List<String> caveats,
        String note) {

    /** A not-yet-run report in the given status (DISABLED / PENDING / UNVERIFIED / SKIPPED). */
    public static ProvenanceReport of(ProvenanceStatus status, String note, List<String> caveats) {
        return new ProvenanceReport(status, null, null, 0, null, null, null, null,
                List.of(), caveats == null ? List.of() : caveats, note);
    }
}
