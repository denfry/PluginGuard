package dev.pluginguard.engine.provenance;

import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.ScanResult;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * What we know about the uploaded artifact for the purpose of finding it on an official source: its
 * declared name/version (from {@code plugin.yml}), the uploaded file name (whose base often carries
 * the real project name even when {@code plugin.yml} declares a different one — e.g. EssentialsX
 * declares "Essentials"), and, if a GitHub repository was referenced in the metadata, that
 * {@code owner/repo}. An {@linkplain #isEmpty() empty} identity cannot be looked up.
 */
public record Identity(String name, String version, String githubOwner, String githubRepo, String fileName) {

    /** GitHub owner/repo as it appears in a URL; skips non-repository owner segments. */
    private static final Pattern GITHUB_REPO = Pattern.compile(
            "(?i)github\\.com/([A-Za-z0-9](?:[A-Za-z0-9-]{0,38})?)/([A-Za-z0-9_.-]{1,100})");
    private static final java.util.Set<String> NON_REPO_OWNERS =
            java.util.Set.of("sponsors", "orgs", "topics", "about", "features", "marketplace", "settings");

    public boolean hasName() {
        return name != null && !name.isBlank();
    }

    public boolean hasGithub() {
        return githubOwner != null && githubRepo != null;
    }

    public boolean hasVersion() {
        return version != null && !version.isBlank();
    }

    public boolean isEmpty() {
        return searchTerms().isEmpty() && !hasGithub();
    }

    /**
     * Distinct names to search official sources for, in priority order: the declared plugin name and
     * a cleaned token from the file name (version/extension stripped). The latter rescues plugins
     * whose marketplace name differs from their {@code plugin.yml} name.
     */
    public List<String> searchTerms() {
        LinkedHashSet<String> terms = new LinkedHashSet<>();
        if (hasName()) {
            terms.add(name.trim());
        }
        String token = fileToken();
        if (token != null) {
            terms.add(token);
        }
        return new ArrayList<>(terms);
    }

    /** A search-friendly token from the file name, or {@code null} if none is usable. */
    private String fileToken() {
        if (fileName == null || fileName.isBlank()) {
            return null;
        }
        String base = fileName.replaceAll("(?i)\\.(jar|zip|mcpack|litemod)$", "");
        // Strip trailing version-ish segments (e.g. "-2.22.0", "-1.21", run twice for "-1.21-2.22.0").
        base = base.replaceAll("(?i)[-_]v?\\d[\\w.]*$", "").replaceAll("(?i)[-_]v?\\d[\\w.]*$", "").trim();
        String lower = base.toLowerCase(Locale.ROOT);
        if (base.length() < 3 || lower.equals("upload") || lower.equals("plugin")) {
            return null;
        }
        return base;
    }

    /** Resolves an identity from a finished static report. */
    public static Identity from(ScanResult result) {
        String name = result.pluginInfo() != null ? trimToNull(result.pluginInfo().name()) : null;
        String version = result.pluginInfo() != null ? trimToNull(result.pluginInfo().version()) : null;
        String[] gh = findGithub(result);
        return new Identity(name, version, gh[0], gh[1], result.fileName());
    }

    /** Scans the report's source links / network indicators for the first plausible GitHub repo. */
    private static String[] findGithub(ScanResult result) {
        for (Finding f : result.findings()) {
            String[] hit = matchGithub(f.evidence());
            if (hit != null) {
                return hit;
            }
            hit = matchGithub(f.description());
            if (hit != null) {
                return hit;
            }
        }
        if (result.summaries() != null) {
            for (String indicator : result.summaries().network()) {
                String[] hit = matchGithub(indicator);
                if (hit != null) {
                    return hit;
                }
            }
        }
        return new String[]{null, null};
    }

    private static String[] matchGithub(String text) {
        if (text == null || text.isBlank()) {
            return null;
        }
        Matcher m = GITHUB_REPO.matcher(text);
        while (m.find()) {
            String owner = m.group(1);
            String repo = m.group(2).replaceAll("\\.git$", "");
            if (!NON_REPO_OWNERS.contains(owner.toLowerCase()) && !repo.isBlank()) {
                return new String[]{owner, repo};
            }
        }
        return null;
    }

    private static String trimToNull(String s) {
        return s == null || s.isBlank() ? null : s.trim();
    }
}
