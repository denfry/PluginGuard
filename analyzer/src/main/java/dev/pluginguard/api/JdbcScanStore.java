package dev.pluginguard.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.pluginguard.engine.model.ScanResult;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.util.Optional;

/**
 * PostgreSQL-backed {@link ScanStore}, active under the {@code postgres} profile.
 *
 * <p>The full {@link ScanResult} is persisted as a single JSONB column (it is already a
 * Jackson-serialized record forming the web API contract, so relational mapping of its nested
 * graph would be wasted effort — reports are always read whole by id). A few fields are projected
 * into columns purely for indexing and retention.
 *
 * <p>{@link #put} is an upsert ({@code ON CONFLICT (id) DO UPDATE}) so the async sandbox can update
 * a report in place (PENDING → RUNNING → COMPLETED).
 */
@Component
@Profile("postgres")
public class JdbcScanStore implements ScanStore {

    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;

    public JdbcScanStore(JdbcTemplate jdbc, ObjectMapper mapper) {
        this.jdbc = jdbc;
        this.mapper = mapper;
    }

    @Override
    public void put(ScanResult result) {
        jdbc.update("""
                INSERT INTO scan (id, sha256, file_name, artifact_type, score, verdict, report)
                VALUES (?, ?, ?, ?, ?, ?, ?::jsonb)
                ON CONFLICT (id) DO UPDATE SET
                    sha256        = EXCLUDED.sha256,
                    file_name     = EXCLUDED.file_name,
                    artifact_type = EXCLUDED.artifact_type,
                    score         = EXCLUDED.score,
                    verdict       = EXCLUDED.verdict,
                    report        = EXCLUDED.report
                """,
                result.id(),
                result.sha256(),
                result.fileName(),
                result.artifactType() == null ? null : result.artifactType().name(),
                result.score(),
                result.verdict() == null ? null : result.verdict().name(),
                serialize(result));
    }

    @Override
    public Optional<ScanResult> get(String id) {
        return jdbc.query("SELECT report FROM scan WHERE id = ?",
                        (rs, rowNum) -> deserialize(rs.getString(1)), id)
                .stream()
                .findFirst();
    }

    private String serialize(ScanResult result) {
        try {
            return mapper.writeValueAsString(result);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize report " + result.id(), e);
        }
    }

    private ScanResult deserialize(String json) {
        try {
            return mapper.readValue(json, ScanResult.class);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to deserialize stored report", e);
        }
    }
}
