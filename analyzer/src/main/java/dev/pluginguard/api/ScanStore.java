package dev.pluginguard.api;

import dev.pluginguard.engine.model.ScanResult;

import java.util.Optional;
import java.util.function.UnaryOperator;

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
 *
 * <p>{@link #update(String, UnaryOperator)} is the <strong>atomic</strong> read-modify-write used by
 * the concurrent async jobs (dynamic sandbox and online provenance) so that each applies only its own
 * section onto the latest stored value, without one clobbering the other's update.
 */
public interface ScanStore {

    /** Stores a report, replacing any existing report with the same id (upsert). */
    void put(ScanResult result);

    /** Returns the stored report for {@code id}, or empty if none. */
    Optional<ScanResult> get(String id);

    /**
     * Atomically applies {@code updater} to the stored report for {@code id} and persists the result.
     * If no report exists for {@code id}, this is a no-op and returns {@code null}. Implementations
     * must serialize concurrent updates to the same id.
     *
     * @return the updated, stored report, or {@code null} if there was nothing to update
     */
    ScanResult update(String id, UnaryOperator<ScanResult> updater);
}
