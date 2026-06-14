package dev.pluginguard.api;

import dev.pluginguard.engine.model.ScanResult;

import java.util.Optional;

/**
 * Persistence port for analyzed reports so the UI can fetch a report by id after upload.
 *
 * <p>Two implementations exist, selected by Spring profile:
 * <ul>
 *   <li>{@link InMemoryScanStore} — default; ephemeral, bounded, lost on restart.</li>
 *   <li>{@link JdbcScanStore} — active under the {@code postgres} profile; durable.</li>
 * </ul>
 *
 * <p>{@link #put(ScanResult)} has <strong>upsert</strong> semantics: the async sandbox updates a
 * report in place (PENDING → RUNNING → COMPLETED), so storing an existing id replaces it.
 */
public interface ScanStore {

    /** Stores a report, replacing any existing report with the same id (upsert). */
    void put(ScanResult result);

    /** Returns the stored report for {@code id}, or empty if none. */
    Optional<ScanResult> get(String id);
}
