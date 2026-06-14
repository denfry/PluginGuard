package dev.pluginguard.api;

import dev.pluginguard.engine.model.ScanResult;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * In-memory, bounded {@link ScanStore} — the default when no durable database is configured.
 * Reports are ephemeral (lost on restart) and the eldest are evicted past {@link #MAX_REPORTS}.
 * Active unless the {@code postgres} profile is on (then {@link JdbcScanStore} takes over).
 */
@Component
@Profile("!postgres")
public class InMemoryScanStore implements ScanStore {

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
