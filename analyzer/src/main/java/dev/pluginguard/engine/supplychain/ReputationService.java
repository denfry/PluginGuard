package dev.pluginguard.engine.supplychain;

import dev.pluginguard.config.AnalyzerProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Loads pull-able SHA-256 reputation lists (known-malicious / known-good) from a configurable
 * source — a local file or an http(s) URL. Remote lists are cached on disk with the same TTL /
 * offline fallback as the OSV client. Each list is one hex SHA-256 per line; blank lines and
 * {@code #} comments are ignored, and anything after the hash on a line is treated as a label.
 */
@Component
public class ReputationService {

    private static final Logger log = LoggerFactory.getLogger(ReputationService.class);

    private final AnalyzerProperties.SupplyChain cfg;
    private final HttpClient http;
    private final DiskCache cache;

    private volatile Set<String> malicious;
    private volatile Set<String> good;

    public ReputationService(AnalyzerProperties properties) {
        this.cfg = properties.getSupplyChain();
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(Math.max(500, cfg.getTimeoutMs())))
                .build();
        this.cache = new DiskCache(cfg.resolveCacheDir().resolve("reputation"),
                Duration.ofHours(cfg.getCacheTtlHours()));
    }

    public Set<String> knownMalicious() {
        Set<String> cached = malicious;
        if (cached == null) {
            cached = loadList(cfg.getKnownMaliciousSource(), "malicious");
            malicious = cached;
        }
        return cached;
    }

    public Set<String> knownGood() {
        Set<String> cached = good;
        if (cached == null) {
            cached = loadList(cfg.getKnownGoodSource(), "good");
            good = cached;
        }
        return cached;
    }

    private Set<String> loadList(String source, String which) {
        if (source == null || source.isBlank()) {
            return Set.of();
        }
        String content = source.startsWith("http://") || source.startsWith("https://")
                ? fetchRemote(source, which)
                : readLocal(source, which);
        return content == null ? Set.of() : parse(content);
    }

    private String readLocal(String source, String which) {
        try {
            return Files.readString(Path.of(source), StandardCharsets.UTF_8);
        } catch (Exception e) {
            log.warn("Could not read {} reputation list '{}': {}", which, source, e.toString());
            return null;
        }
    }

    private String fetchRemote(String source, String which) {
        String key = which + "/" + source;
        var fresh = cache.get(key);
        if (fresh.isPresent()) {
            return fresh.get();
        }
        if (cfg.isOffline()) {
            return cache.getStale(key).orElse(null);
        }
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(source))
                    .timeout(Duration.ofMillis(Math.max(500, cfg.getTimeoutMs())))
                    .GET()
                    .build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                cache.put(key, response.body());
                return response.body();
            }
            log.warn("Reputation list '{}' returned HTTP {}", source, response.statusCode());
        } catch (Exception e) {
            log.warn("Could not fetch {} reputation list '{}': {}", which, source, e.toString());
        }
        return cache.getStale(key).orElse(null);
    }

    private Set<String> parse(String content) {
        Set<String> out = new HashSet<>();
        for (String line : content.split("\\r?\\n")) {
            String trimmed = line.trim();
            if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                continue;
            }
            String hash = trimmed.split("\\s+")[0].toLowerCase(Locale.ROOT);
            if (hash.matches("[0-9a-f]{64}")) {
                out.add(hash);
            }
        }
        return out;
    }
}
