package dev.pluginguard.api;

import dev.pluginguard.engine.model.ScanResult;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * In-memory, bounded store of recent reports so the UI can fetch a report by id after upload.
 * Reports are ephemeral (lost on restart); a durable database is a later phase.
 */
@Component
public class ScanStore {

    private static final int MAX_REPORTS = 500;

    private final Map<String, ScanResult> reports = Collections.synchronizedMap(
            new LinkedHashMap<>(16, 0.75f, false) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, ScanResult> eldest) {
                    return size() > MAX_REPORTS;
                }
            });

    public void put(ScanResult result) {
        reports.put(result.id(), result);
    }

    public Optional<ScanResult> get(String id) {
        return Optional.ofNullable(reports.get(id));
    }
}
