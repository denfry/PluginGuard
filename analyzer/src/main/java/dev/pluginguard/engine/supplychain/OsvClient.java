package dev.pluginguard.engine.supplychain;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.pluginguard.config.AnalyzerProperties;
import dev.pluginguard.engine.model.Severity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Queries <a href="https://osv.dev">OSV.dev</a> for known vulnerabilities affecting a dependency
 * coordinate, with a TTL disk cache and soft offline degradation. The client never throws on a
 * network problem: it reports the lookup as <em>unavailable</em> (falling back to a stale cache
 * entry when one exists) so the analyzer can add an honest note instead of failing the scan.
 */
@Component
public class OsvClient {

    private static final Logger log = LoggerFactory.getLogger(OsvClient.class);

    private final AnalyzerProperties.SupplyChain cfg;
    private final HttpClient http;
    private final ObjectMapper mapper = new ObjectMapper();
    private final DiskCache cache;

    public OsvClient(AnalyzerProperties properties) {
        this.cfg = properties.getSupplyChain();
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(Math.max(500, cfg.getTimeoutMs())))
                .build();
        this.cache = new DiskCache(cfg.resolveCacheDir().resolve("osv"),
                Duration.ofHours(cfg.getCacheTtlHours()));
    }

    /** A package coordinate to look up. */
    public record Coordinate(String ecosystem, String name, String version) {
        String cacheKey() {
            return ecosystem + "/" + name + "/" + version;
        }
    }

    /** One vulnerability OSV reported for a coordinate. */
    public record OsvVuln(String id, String summary, Severity severity, String url) {
    }

    /**
     * Outcome of a lookup. {@code available == false} means we could not reach OSV and had no
     * cached answer, so absence of vulns is unknown (not a clean bill of health).
     */
    public record QueryOutcome(boolean available, List<OsvVuln> vulns) {
        static QueryOutcome unavailable() {
            return new QueryOutcome(false, List.of());
        }
    }

    public QueryOutcome query(Coordinate coord) {
        String key = coord.cacheKey();

        // 1. Fresh cache hit.
        var fresh = cache.get(key);
        if (fresh.isPresent()) {
            return new QueryOutcome(true, parse(fresh.get()));
        }
        // 2. Offline switch — use a stale entry if we have one, otherwise give up gracefully.
        if (cfg.isOffline()) {
            return cache.getStale(key)
                    .map(body -> new QueryOutcome(true, parse(body)))
                    .orElseGet(QueryOutcome::unavailable);
        }
        // 3. Network with bounded retries; cache the body on success.
        String body = fetch(coord);
        if (body != null) {
            cache.put(key, body);
            return new QueryOutcome(true, parse(body));
        }
        // 4. Network failed — fall back to any stale cache entry.
        return cache.getStale(key)
                .map(b -> new QueryOutcome(true, parse(b)))
                .orElseGet(QueryOutcome::unavailable);
    }

    private String fetch(Coordinate coord) {
        String payload = "{\"package\":{\"ecosystem\":\"" + esc(coord.ecosystem())
                + "\",\"name\":\"" + esc(coord.name()) + "\"},\"version\":\"" + esc(coord.version()) + "\"}";
        HttpRequest request = HttpRequest.newBuilder(URI.create(cfg.getOsvApiUrl()))
                .timeout(Duration.ofMillis(Math.max(500, cfg.getTimeoutMs())))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(payload))
                .build();

        int attempts = Math.max(1, cfg.getRetries() + 1);
        for (int i = 0; i < attempts; i++) {
            try {
                HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() == 200) {
                    return response.body();
                }
                log.debug("OSV query for {} returned HTTP {}", coord.name(), response.statusCode());
            } catch (Exception e) {
                log.debug("OSV query for {} failed (attempt {}/{}): {}", coord.name(), i + 1, attempts, e.toString());
            }
        }
        return null;
    }

    private List<OsvVuln> parse(String body) {
        List<OsvVuln> out = new ArrayList<>();
        try {
            JsonNode root = mapper.readTree(body);
            for (JsonNode v : root.path("vulns")) {
                String id = v.path("id").asText("");
                if (id.isEmpty()) {
                    continue;
                }
                String summary = v.path("summary").asText("");
                if (summary.isBlank()) {
                    summary = v.path("details").asText("");
                }
                out.add(new OsvVuln(id, truncate(summary), severityOf(v),
                        "https://osv.dev/vulnerability/" + id));
            }
        } catch (Exception e) {
            log.debug("Could not parse OSV response: {}", e.toString());
        }
        return out;
    }

    /** Derives a severity from the GHSA qualitative label, else from a CVSS v3 vector, else MEDIUM. */
    private Severity severityOf(JsonNode vuln) {
        JsonNode dbSeverity = vuln.path("database_specific").path("severity");
        if (dbSeverity.isTextual()) {
            return mapLabel(dbSeverity.asText());
        }
        for (JsonNode s : vuln.path("severity")) {
            Double score = Cvss.baseScore(s.path("score").asText(""));
            if (score != null) {
                return mapScore(score);
            }
        }
        return Severity.MEDIUM;
    }

    private static Severity mapLabel(String label) {
        return switch (label.trim().toUpperCase()) {
            case "CRITICAL" -> Severity.CRITICAL;
            case "HIGH" -> Severity.HIGH;
            case "MODERATE", "MEDIUM" -> Severity.MEDIUM;
            case "LOW" -> Severity.LOW;
            default -> Severity.MEDIUM;
        };
    }

    private static Severity mapScore(double score) {
        if (score >= 9.0) return Severity.CRITICAL;
        if (score >= 7.0) return Severity.HIGH;
        if (score >= 4.0) return Severity.MEDIUM;
        if (score > 0.0) return Severity.LOW;
        return Severity.MEDIUM;
    }

    private static String esc(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String truncate(String s) {
        if (s == null) {
            return "";
        }
        return s.length() <= 200 ? s : s.substring(0, 197) + "...";
    }
}
