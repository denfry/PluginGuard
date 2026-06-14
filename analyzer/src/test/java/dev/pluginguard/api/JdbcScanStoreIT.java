package dev.pluginguard.api;

import dev.pluginguard.engine.model.ScanResult;
import dev.pluginguard.engine.model.Verdict;
import dev.pluginguard.support.AbstractPostgresIT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for {@link JdbcScanStore} against a real PostgreSQL: JSONB round-trip and the
 * upsert semantics the async sandbox relies on.
 */
class JdbcScanStoreIT extends AbstractPostgresIT {

    @Autowired
    private ScanStore store;
    @Autowired
    private JdbcTemplate jdbc;

    @BeforeEach
    void clean() {
        jdbc.execute("TRUNCATE scan");
    }

    @Test
    void usesTheJdbcImplementationUnderPostgresProfile() {
        assertThat(store).isInstanceOf(JdbcScanStore.class);
    }

    @Test
    void storesAndReadsBackAReport() {
        ScanResult sample = DemoData.sample();

        store.put(sample);
        ScanResult got = store.get(sample.id()).orElseThrow();

        assertThat(got.id()).isEqualTo(sample.id());
        assertThat(got.score()).isEqualTo(sample.score());
        assertThat(got.verdict()).isEqualTo(sample.verdict());
        assertThat(got.findings()).hasSameSizeAs(sample.findings());
        assertThat(got.analyzedAt()).isEqualTo(sample.analyzedAt());
    }

    @Test
    void putUpsertsInPlaceWithoutDuplicatingRows() {
        ScanResult v1 = DemoData.sample();
        store.put(v1);

        // Same id, changed verdict + a distinctive note — mirrors the sandbox PENDING→COMPLETED update.
        ScanResult v2 = v1.withSandbox(v1.sandbox(), Verdict.CRITICAL_RISK, List.of("UPSERTED"));
        store.put(v2);

        ScanResult got = store.get(v1.id()).orElseThrow();
        assertThat(got.verdict()).isEqualTo(Verdict.CRITICAL_RISK);
        assertThat(got.notes()).contains("UPSERTED");

        Integer rows = jdbc.queryForObject("SELECT count(*) FROM scan WHERE id = ?", Integer.class, v1.id());
        assertThat(rows).isEqualTo(1);
        // The projected column is kept in sync with the JSONB on conflict.
        String verdictColumn = jdbc.queryForObject("SELECT verdict FROM scan WHERE id = ?", String.class, v1.id());
        assertThat(verdictColumn).isEqualTo(Verdict.CRITICAL_RISK.name());
    }

    @Test
    void getReturnsEmptyForUnknownId() {
        assertThat(store.get("does-not-exist")).isEmpty();
    }
}
