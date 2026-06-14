package dev.pluginguard.engine.provenance;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.pluginguard.config.AnalyzerProperties;
import dev.pluginguard.engine.supplychain.DiskCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;

/**
 * Shared HTTP access for the official-source clients: a {@link HttpClient} with a TTL disk cache for
 * JSON responses and a size-capped binary download for the official jar. JSON GETs distinguish three
 * outcomes — {@code 200} returns the parsed body, {@code 404} returns {@link Optional#empty()} (a
 * clean "not listed here"), and a transport/5xx error after retries throws {@link ProvenanceException}
 * so the verifier can tell "not found" apart from "couldn't check".
 */
@Component
public class ProvenanceHttp {

    private static final Logger log = LoggerFactory.getLogger(ProvenanceHttp.class);

    private final AnalyzerProperties.Provenance cfg;
    private final HttpClient http;
    private final ObjectMapper mapper = new ObjectMapper();
    private final DiskCache cache;

    public ProvenanceHttp(AnalyzerProperties properties) {
        this.cfg = properties.getProvenance();
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(Math.max(500, cfg.getTimeoutMs())))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
        this.cache = new DiskCache(cfg.resolveCacheDir().resolve("provenance"),
                Duration.ofHours(cfg.getCacheTtlHours()));
    }

    /**
     * GETs a JSON document. Returns the parsed body on 200 (cached), empty on 404, and throws
     * {@link ProvenanceException} on a transport error or non-200/404 status after retries.
     */
    public Optional<JsonNode> getJson(String url, Map<String, String> headers) {
        Optional<String> cached = cache.get(url);
        if (cached.isPresent()) {
            return parse(cached.get());
        }
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofMillis(Math.max(500, cfg.getTimeoutMs())))
                .header("User-Agent", cfg.getUserAgent())
                .header("Accept", "application/json")
                .GET();
        headers.forEach(builder::header);
        HttpRequest request = builder.build();

        int attempts = Math.max(1, cfg.getRetries() + 1);
        RuntimeException last = null;
        for (int i = 0; i < attempts; i++) {
            try {
                HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
                int code = response.statusCode();
                if (code == 200) {
                    cache.put(url, response.body());
                    return parse(response.body());
                }
                if (code == 404) {
                    return Optional.empty();
                }
                last = new ProvenanceException("GET " + url + " returned HTTP " + code);
                log.debug("{}", last.getMessage());
            } catch (Exception e) {
                last = new ProvenanceException("GET " + url + " failed: " + e, e);
                log.debug("GET {} failed (attempt {}/{}): {}", url, i + 1, attempts, e.toString());
            }
        }
        throw last != null ? last : new ProvenanceException("GET " + url + " failed");
    }

    /**
     * Downloads a binary artifact, refusing anything larger than {@code maxBytes}. Returns the bytes,
     * or empty when the response is non-200 or exceeds the cap. Throws {@link ProvenanceException} on
     * a transport error.
     */
    public Optional<byte[]> download(String url, long maxBytes) {
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofMillis(Math.max(2000, cfg.getTimeoutMs() * 4L)))
                .header("User-Agent", cfg.getUserAgent())
                .GET()
                .build();
        try {
            HttpResponse<InputStream> response = http.send(request, HttpResponse.BodyHandlers.ofInputStream());
            if (response.statusCode() != 200) {
                log.debug("Download {} returned HTTP {}", url, response.statusCode());
                return Optional.empty();
            }
            try (InputStream in = response.body();
                 var out = new java.io.ByteArrayOutputStream()) {
                byte[] buf = new byte[16 * 1024];
                long total = 0;
                int n;
                while ((n = in.read(buf)) != -1) {
                    total += n;
                    if (total > maxBytes) {
                        log.debug("Download {} exceeds {} bytes; aborting", url, maxBytes);
                        return Optional.empty();
                    }
                    out.write(buf, 0, n);
                }
                return Optional.of(out.toByteArray());
            }
        } catch (Exception e) {
            throw new ProvenanceException("Download " + url + " failed: " + e, e);
        }
    }

    private Optional<JsonNode> parse(String body) {
        try {
            return Optional.of(mapper.readTree(body));
        } catch (Exception e) {
            throw new ProvenanceException("Could not parse JSON: " + e, e);
        }
    }
}
