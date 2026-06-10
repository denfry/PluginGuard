package dev.pluginguard.api;

import dev.pluginguard.engine.model.ScanResult;

import java.util.Optional;

/**
 * Stores generated reports so the UI can fetch one by id after upload ({@code GET /api/scan/{id}}).
 *
 * <p>Two implementations exist: the in-memory {@link ScanStore} (default — ephemeral, lost on
 * restart) and {@link JdbcReportStore}, a PostgreSQL-backed store that survives restarts and
 * spin-downs. The active one is selected by {@code pluginguard.persistence} ({@code memory} |
 * {@code jdbc}); see {@link PersistenceConfig}.
 */
public interface ReportStore {

    /** Stores a report, replacing any existing one with the same id. */
    void put(ScanResult result);

    /** Returns the report with the given id, if present. */
    Optional<ScanResult> get(String id);
}
