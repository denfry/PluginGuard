package dev.pluginguard.engine.sandbox;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.pluginguard.engine.model.BehaviorEvent;

import java.util.ArrayList;
import java.util.List;

/**
 * Parses the container's JSON Lines behavior log into {@link BehaviorEvent}s. Lenient by design:
 * blank or malformed lines are skipped so a truncated log (e.g. from a timed-out run) still yields
 * the events written before the cut-off.
 */
public final class BehaviorLogParser {

    private final ObjectMapper mapper = new ObjectMapper();

    public List<BehaviorEvent> parse(String jsonl) {
        List<BehaviorEvent> events = new ArrayList<>();
        if (jsonl == null || jsonl.isBlank()) {
            return events;
        }
        for (String line : jsonl.split("\\R")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            try {
                JsonNode n = mapper.readTree(trimmed);
                if (!n.isObject() || !n.hasNonNull("type")) {
                    continue;
                }
                events.add(new BehaviorEvent(
                        n.path("type").asText(),
                        text(n, "target"),
                        text(n, "detail"),
                        text(n, "source"),
                        n.path("blocked").asBoolean(false)));
            } catch (Exception ignored) {
                // skip an unparseable line; keep the rest
            }
        }
        return events;
    }

    private static String text(JsonNode n, String field) {
        JsonNode v = n.get(field);
        return v == null || v.isNull() ? null : v.asText();
    }
}
