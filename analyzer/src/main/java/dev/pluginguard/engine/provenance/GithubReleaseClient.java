package dev.pluginguard.engine.provenance;

import com.fasterxml.jackson.databind.JsonNode;
import dev.pluginguard.config.AnalyzerProperties;
import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * <a href="https://github.com">GitHub Releases</a> source, used when the metadata references a repo.
 * GitHub has no asset-hash API, so this only locates the matching release asset; the verifier
 * downloads it (size-capped) and compares the bytes directly.
 */
@Component
public class GithubReleaseClient implements OfficialSource {

    private final AnalyzerProperties.Provenance cfg;
    private final ProvenanceHttp http;

    public GithubReleaseClient(AnalyzerProperties properties, ProvenanceHttp http) {
        this.cfg = properties.getProvenance();
        this.http = http;
    }

    @Override
    public String displayName() {
        return "GitHub";
    }

    @Override
    public Optional<OfficialRelease> findRelease(Identity id) {
        if (!id.hasGithub() || !id.hasVersion()) {
            return Optional.empty();
        }
        Optional<JsonNode> releases = http.getJson(
                cfg.getGithubApiUrl() + "/repos/" + id.githubOwner() + "/" + id.githubRepo()
                        + "/releases?per_page=30", headers());
        if (releases.isEmpty() || !releases.get().isArray()) {
            return Optional.empty();
        }
        for (JsonNode release : releases.get()) {
            if (tagMatches(release.path("tag_name").asText(""), id.version())) {
                JsonNode asset = pickJarAsset(release, id.version());
                if (asset == null) {
                    return Optional.empty();
                }
                return Optional.of(new OfficialRelease(
                        displayName(),
                        id.githubOwner() + "/" + id.githubRepo(),
                        release.path("html_url").asText(
                                "https://github.com/" + id.githubOwner() + "/" + id.githubRepo() + "/releases"),
                        release.path("tag_name").asText(id.version()),
                        asset.path("name").asText(null),
                        null,   // GitHub exposes no asset hash — compare by download
                        null,
                        asset.path("browser_download_url").asText(null)));
            }
        }
        return Optional.empty();
    }

    private Map<String, String> headers() {
        if (cfg.getGithubToken() != null && !cfg.getGithubToken().isBlank()) {
            return Map.of("Accept", "application/vnd.github+json",
                    "Authorization", "Bearer " + cfg.getGithubToken());
        }
        return Map.of("Accept", "application/vnd.github+json");
    }

    /** Tolerant tag/version comparison ({@code v1.2.3} ≈ {@code 1.2.3}). */
    private static boolean tagMatches(String tag, String version) {
        if (tag.isBlank()) {
            return false;
        }
        String t = normalize(tag);
        String v = normalize(version);
        return t.equals(v) || t.endsWith(v) || t.contains(v);
    }

    private static String normalize(String s) {
        return s.toLowerCase(Locale.ROOT).replaceFirst("^v", "").trim();
    }

    private static JsonNode pickJarAsset(JsonNode release, String version) {
        JsonNode assets = release.path("assets");
        if (!assets.isArray() || assets.isEmpty()) {
            return null;
        }
        JsonNode firstJar = null;
        for (JsonNode a : assets) {
            String name = a.path("name").asText("").toLowerCase(Locale.ROOT);
            if (name.endsWith(".jar")) {
                if (name.contains(normalize(version))) {
                    return a; // a versioned jar is the best match
                }
                if (firstJar == null) {
                    firstJar = a;
                }
            }
        }
        return firstJar;
    }
}
