package dev.pluginguard.engine.provenance;

import com.fasterxml.jackson.databind.JsonNode;
import dev.pluginguard.config.AnalyzerProperties;
import org.springframework.stereotype.Component;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * <a href="https://hangar.papermc.io">Hangar</a> (PaperMC) source. Hangar exposes a per-download
 * {@code sha256Hash}, so the comparison path works without downloading. JSON shapes are read
 * defensively — a missing field degrades to "not listed here" rather than an error.
 */
@Component
public class HangarClient implements OfficialSource {

    /** Top hits to inspect per search term — a generic word returns many unrelated projects. */
    private static final int MAX_HITS_PER_TERM = 4;

    private final AnalyzerProperties.Provenance cfg;
    private final ProvenanceHttp http;

    public HangarClient(AnalyzerProperties properties, ProvenanceHttp http) {
        this.cfg = properties.getProvenance();
        this.http = http;
    }

    @Override
    public String displayName() {
        return "Hangar";
    }

    @Override
    public Optional<OfficialRelease> findRelease(Identity id) {
        if (!id.hasVersion() || id.searchTerms().isEmpty()) {
            return Optional.empty();
        }
        Set<String> triedSlugs = new HashSet<>();
        for (String term : id.searchTerms()) {
            String query = URLEncoder.encode(term, StandardCharsets.UTF_8);
            Optional<JsonNode> search = http.getJson(
                    cfg.getHangarApiUrl() + "/projects?limit=5&q=" + query, Map.of());
            if (search.isEmpty()) {
                continue;
            }
            JsonNode result = search.get().path("result");
            if (!result.isArray()) {
                continue;
            }
            int checked = 0;
            for (JsonNode project : result) {
                if (checked++ >= MAX_HITS_PER_TERM) {
                    break;
                }
                String slug = project.path("namespace").path("slug").asText("");
                if (slug.isBlank() || !triedSlugs.add(slug)) {
                    continue;
                }
                Optional<OfficialRelease> release = releaseForVersion(
                        project, project.path("namespace").path("owner").asText(""), slug, id.version());
                if (release.isPresent()) {
                    return release;
                }
            }
        }
        return Optional.empty();
    }

    /** Resolves the given version of one project to a downloadable release, if it exists. */
    private Optional<OfficialRelease> releaseForVersion(JsonNode project, String owner, String slug, String version) {
        Optional<JsonNode> versions = http.getJson(
                cfg.getHangarApiUrl() + "/projects/" + slug + "/versions?limit=25", Map.of());
        if (versions.isEmpty()) {
            return Optional.empty();
        }
        JsonNode result = versions.get().path("result");
        if (!result.isArray()) {
            return Optional.empty();
        }
        for (JsonNode v : result) {
            if (v.path("name").asText("").equalsIgnoreCase(version)) {
                return buildRelease(project, owner, slug, v);
            }
        }
        return Optional.empty();
    }

    /** Picks the first platform download that carries a sha256, and builds the release from it. */
    private Optional<OfficialRelease> buildRelease(JsonNode project, String owner, String slug, JsonNode version) {
        JsonNode downloads = version.path("downloads");
        for (Map.Entry<String, JsonNode> e : downloads.properties()) {
            String platform = e.getKey();
            JsonNode entry = e.getValue();
            JsonNode info = entry.path("fileInfo");
            String sha256 = info.path("sha256Hash").asText("");
            if (!sha256.isBlank()) {
                String versionName = version.path("name").asText("");
                // Prefer the CDN URL Hangar returns; fall back to the API download endpoint.
                String downloadUrl = entry.path("downloadUrl").asText(null);
                if (downloadUrl == null || downloadUrl.isBlank()) {
                    downloadUrl = cfg.getHangarApiUrl() + "/projects/" + slug + "/versions/"
                            + URLEncoder.encode(versionName, StandardCharsets.UTF_8) + "/" + platform + "/download";
                }
                return Optional.of(new OfficialRelease(
                        displayName(),
                        project.path("name").asText(slug),
                        "https://hangar.papermc.io/" + owner + "/" + slug,
                        versionName,
                        info.path("name").asText(null),
                        "sha256",
                        sha256,
                        downloadUrl));
            }
        }
        return Optional.empty();
    }
}
