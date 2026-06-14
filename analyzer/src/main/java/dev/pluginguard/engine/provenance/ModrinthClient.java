package dev.pluginguard.engine.provenance;

import com.fasterxml.jackson.databind.JsonNode;
import dev.pluginguard.config.AnalyzerProperties;
import dev.pluginguard.engine.model.ProvenanceMatch;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * <a href="https://modrinth.com">Modrinth</a> source. Its {@code /version_file/{hash}} endpoint maps a
 * file hash straight to its project + version, so an uploaded jar can be confirmed authentic by hash
 * alone (no download). A name+version search backs the comparison path when the hash is unknown.
 */
@Component
public class ModrinthClient implements OfficialSource {

    private static final Logger log = LoggerFactory.getLogger(ModrinthClient.class);

    private final AnalyzerProperties.Provenance cfg;
    private final ProvenanceHttp http;

    public ModrinthClient(AnalyzerProperties properties, ProvenanceHttp http) {
        this.cfg = properties.getProvenance();
        this.http = http;
    }

    @Override
    public String displayName() {
        return "Modrinth";
    }

    @Override
    public Optional<ProvenanceMatch> lookupByHash(String sha1, String sha512) {
        Optional<JsonNode> version = http.getJson(
                cfg.getModrinthApiUrl() + "/version_file/" + sha512 + "?algorithm=sha512", Map.of());
        if (version.isEmpty()) {
            version = http.getJson(
                    cfg.getModrinthApiUrl() + "/version_file/" + sha1 + "?algorithm=sha1", Map.of());
        }
        if (version.isEmpty()) {
            return Optional.empty();
        }
        JsonNode v = version.get();
        JsonNode file = pickFileByHash(v, sha512, sha1);
        Project project = enrichProject(v.path("project_id").asText(""));
        return Optional.of(new ProvenanceMatch(
                displayName(),
                project.name(),
                project.url(),
                v.path("version_number").asText(null),
                file == null ? null : file.path("filename").asText(null),
                file == null ? sha512 : file.path("hashes").path("sha512").asText(sha512),
                file == null ? null : file.path("url").asText(null),
                true));
    }

    /** Top hits to inspect per search term — a generic word (e.g. "Essentials") returns many plugins. */
    private static final int MAX_HITS_PER_TERM = 4;

    @Override
    public Optional<OfficialRelease> findRelease(Identity id) {
        if (!id.hasVersion() || id.searchTerms().isEmpty()) {
            return Optional.empty();
        }
        Set<String> triedSlugs = new HashSet<>();
        for (String term : id.searchTerms()) {
            String query = URLEncoder.encode(term, StandardCharsets.UTF_8);
            Optional<JsonNode> search = http.getJson(
                    cfg.getModrinthApiUrl() + "/search?limit=5&query=" + query, Map.of());
            if (search.isEmpty()) {
                continue;
            }
            int checked = 0;
            for (JsonNode hit : search.get().path("hits")) {
                if (checked++ >= MAX_HITS_PER_TERM) {
                    break;
                }
                String slug = hit.path("slug").asText(hit.path("project_id").asText(""));
                if (slug.isBlank() || !triedSlugs.add(slug)) {
                    continue;
                }
                Optional<OfficialRelease> release = releaseForVersion(hit, slug, id.version());
                if (release.isPresent()) {
                    return release;
                }
            }
        }
        return Optional.empty();
    }

    /** Resolves the given version of one project to a downloadable release, if it exists. */
    private Optional<OfficialRelease> releaseForVersion(JsonNode hit, String slug, String version) {
        Optional<JsonNode> versions = http.getJson(
                cfg.getModrinthApiUrl() + "/project/" + slug + "/version", Map.of());
        if (versions.isEmpty() || !versions.get().isArray()) {
            return Optional.empty();
        }
        for (JsonNode v : versions.get()) {
            if (v.path("version_number").asText("").equalsIgnoreCase(version)) {
                JsonNode file = pickPrimaryFile(v);
                if (file == null) {
                    return Optional.empty();
                }
                String type = hit.path("project_type").asText("mod");
                return Optional.of(new OfficialRelease(
                        displayName(),
                        hit.path("title").asText(slug),
                        "https://modrinth.com/" + type + "/" + slug,
                        v.path("version_number").asText(version),
                        file.path("filename").asText(null),
                        "sha512",
                        file.path("hashes").path("sha512").asText(null),
                        file.path("url").asText(null)));
            }
        }
        return Optional.empty();
    }

    /** Fetches title + a correct public URL for a project id; falls back to the id on any error. */
    private Project enrichProject(String projectId) {
        if (projectId.isBlank()) {
            return new Project(projectId, "https://modrinth.com");
        }
        try {
            Optional<JsonNode> p = http.getJson(cfg.getModrinthApiUrl() + "/project/" + projectId, Map.of());
            if (p.isPresent()) {
                String slug = p.get().path("slug").asText(projectId);
                String type = p.get().path("project_type").asText("mod");
                return new Project(p.get().path("title").asText(slug), "https://modrinth.com/" + type + "/" + slug);
            }
        } catch (ProvenanceException e) {
            log.debug("Modrinth project enrich failed for {}: {}", projectId, e.toString());
        }
        return new Project(projectId, "https://modrinth.com/mod/" + projectId);
    }

    private static JsonNode pickFileByHash(JsonNode version, String sha512, String sha1) {
        JsonNode files = version.path("files");
        if (!files.isArray()) {
            return null;
        }
        for (JsonNode f : files) {
            JsonNode h = f.path("hashes");
            if (h.path("sha512").asText("").equalsIgnoreCase(sha512)
                    || h.path("sha1").asText("").equalsIgnoreCase(sha1)) {
                return f;
            }
        }
        return pickPrimaryFile(version);
    }

    private static JsonNode pickPrimaryFile(JsonNode version) {
        JsonNode files = version.path("files");
        if (!files.isArray() || files.isEmpty()) {
            return null;
        }
        for (JsonNode f : files) {
            if (f.path("primary").asBoolean(false)) {
                return f;
            }
        }
        for (JsonNode f : files) {
            if (f.path("filename").asText("").toLowerCase().endsWith(".jar")) {
                return f;
            }
        }
        return files.get(0);
    }

    private record Project(String name, String url) {
    }
}
