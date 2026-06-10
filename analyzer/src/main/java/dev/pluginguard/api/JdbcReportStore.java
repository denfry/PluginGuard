package dev.pluginguard.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.pluginguard.engine.model.ScanResult;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;
import java.util.Optional;

/**
 * PostgreSQL-backed {@link ReportStore}. Each report is persisted as the very JSON the API returns
 * (keyed by its id), so reports survive restarts and free-tier spin-downs. Active only when
 * {@code pluginguard.persistence=jdbc} (wired by {@link PersistenceConfig}).
 */
public class JdbcReportStore implements ReportStore {

    private static final Logger log = LoggerFactory.getLogger(JdbcReportStore.class);

    /** Keep only the most recent reports so a small free database can't grow unbounded. */
    private static final int MAX_REPORTS = 1000;

    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;

    public JdbcReportStore(JdbcTemplate jdbc, ObjectMapper mapper) {
        this.jdbc = jdbc;
        this.mapper = mapper;
    }

    @PostConstruct
    void createSchema() {
        jdbc.execute("""
                CREATE TABLE IF NOT EXISTS reports (
                    id         VARCHAR(64) PRIMARY KEY,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    payload    TEXT        NOT NULL
                )
                """);
        log.info("JDBC report store ready — reports are durable.");
    }

    @Override
    public void put(ScanResult result) {
        String payload;
        try {
            payload = mapper.writeValueAsString(result);
        } catch (Exception e) {
            throw new IllegalStateException("Could not serialize report " + result.id(), e);
        }
        // Upsert: the sandbox flow stores the same id several times (PENDING → RUNNING → COMPLETED).
        jdbc.update("""
                INSERT INTO reports (id, payload) VALUES (?, ?)
                ON CONFLICT (id) DO UPDATE SET payload = EXCLUDED.payload, created_at = now()
                """, result.id(), payload);
        // Bounded retention: drop everything past the newest MAX_REPORTS rows.
        jdbc.update("DELETE FROM reports WHERE id IN "
                + "(SELECT id FROM reports ORDER BY created_at DESC OFFSET ?)", MAX_REPORTS);
    }

    @Override
    public Optional<ScanResult> get(String id) {
        List<String> rows = jdbc.query(
                "SELECT payload FROM reports WHERE id = ?",
                (rs, rowNum) -> rs.getString(1), id);
        if (rows.isEmpty()) {
            return Optional.empty();
        }
        try {
            return Optional.of(mapper.readValue(rows.get(0), ScanResult.class));
        } catch (Exception e) {
            // A format change could leave an unreadable row; treat it as missing rather than 500.
            log.warn("Could not deserialize stored report {}: {}", id, e.toString());
            return Optional.empty();
        }
    }
}
