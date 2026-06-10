package dev.pluginguard.api;

import dev.pluginguard.engine.model.ScanResult;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * In-memory, bounded {@link ReportStore} — the default. Reports are ephemeral (lost on restart and
 * not shared across instances). For durable reports, set {@code pluginguard.persistence=jdbc} to use
 * {@link JdbcReportStore} instead.
 */
@Component
@ConditionalOnProperty(prefix = "pluginguard", name = "persistence", havingValue = "memory",
        matchIfMissing = true)
public class ScanStore implements ReportStore {

    private static final int MAX_REPORTS = 500;

    private final Map<String, ScanResult> reports = Collections.synchronizedMap(
            new LinkedHashMap<>(16, 0.75f, false) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, ScanResult> eldest) {
                    return size() > MAX_REPORTS;
                }
            });

    @Override
    public void put(ScanResult result) {
        reports.put(result.id(), result);
    }

    @Override
    public Optional<ScanResult> get(String id) {
        return Optional.ofNullable(reports.get(id));
    }
}
