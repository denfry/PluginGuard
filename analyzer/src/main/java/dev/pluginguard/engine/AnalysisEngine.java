package dev.pluginguard.engine;

import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.bytecode.ClassScanner;
import dev.pluginguard.engine.model.Category;
import dev.pluginguard.engine.model.ClassFile;
import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.JarModel;
import dev.pluginguard.engine.model.PluginInfo;
import dev.pluginguard.engine.model.ScanResult;
import dev.pluginguard.engine.model.Severity;
import dev.pluginguard.engine.model.SeverityCounts;
import dev.pluginguard.engine.model.Summaries;
import dev.pluginguard.engine.model.Verdict;
import dev.pluginguard.scoring.ScoreCalculator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import dev.pluginguard.engine.model.ResourceFile;

import java.time.Instant;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Orchestrates the static analysis pipeline: load the JAR, scan every class once with ASM, run all
 * {@link Analyzer}s (in {@code @Order}), then score and assemble the {@link ScanResult}.
 */
@Service
public class AnalysisEngine {

    public static final String ENGINE_VERSION = "0.1.0";

    private static final Logger log = LoggerFactory.getLogger(AnalysisEngine.class);

    /** Severity first (CRITICAL→INFO), then larger score impact first. */
    private static final Comparator<Finding> FINDING_ORDER =
            Comparator.comparingInt((Finding f) -> f.severity().ordinal())
                    .thenComparing(Comparator.comparingInt(Finding::scoreImpact).reversed());

    private final JarLoader jarLoader;
    private final List<Analyzer> analyzers;
    private final ScoreCalculator scoreCalculator;

    public AnalysisEngine(JarLoader jarLoader, List<Analyzer> analyzers, ScoreCalculator scoreCalculator) {
        this.jarLoader = jarLoader;
        this.analyzers = analyzers;
        this.scoreCalculator = scoreCalculator;
    }

    public ScanResult analyze(String id, String fileName, byte[] data) {
        long start = System.currentTimeMillis();

        JarModel jar = jarLoader.load(fileName, data);
        List<ClassScan> classScans = jar.classes().stream()
                .map(ClassScanner::scan)
                .toList();

        AnalysisContext ctx = new AnalysisContext(jar, classScans);

        for (Analyzer analyzer : analyzers) {
            try {
                analyzer.analyze(ctx);
            } catch (RuntimeException e) {
                log.warn("Analyzer '{}' failed: {}", analyzer.name(), e.toString());
                ctx.addNote("Analyzer '" + analyzer.name() + "' failed and was skipped: " + e.getMessage());
            }
        }

        addProvenanceNotice(ctx);

        List<Finding> findings = ctx.findings().stream().sorted(FINDING_ORDER).toList();
        int score = scoreCalculator.score(findings);
        SeverityCounts counts = SeverityCounts.from(findings);
        Verdict verdict = Verdict.from(score, counts);
        PluginInfo info = ctx.pluginInfo();

        Summaries summaries = new Summaries(
                ctx.network(), ctx.filesystem(), ctx.dependencies(),
                classScans.size(), ctx.methodCount());

        long duration = System.currentTimeMillis() - start;
        log.info("Analyzed '{}' ({} classes) -> score {} ({}) in {} ms",
                fileName, classScans.size(), score, verdict.getLabel(), duration);

        return new ScanResult(
                id,
                fileName,
                jar.sha256(),
                jar.sizeBytes(),
                ctx.platform(),
                ctx.artifactType(),
                info != null ? info.main() : null,
                info != null ? info.apiVersion() : null,
                score,
                verdict,
                ctx.obfuscationScore(),
                counts,
                info,
                findings,
                summaries,
                ctx.notes(),
                Instant.now(),
                duration,
                ENGINE_VERSION,
                null,  // dynamic sandbox section is attached later by SandboxService, if enabled
                null); // online provenance section is attached later by ProvenanceService, if enabled
    }

    /**
     * Matches a source repository or official-listing reference — with or without a scheme, with any
     * subdomain (so {@code https://github.com/x/y}, {@code github.com/x/y} and {@code api.github.com}
     * all match) and an optional path. The hosts are public repos and the well-known Minecraft
     * plugin/mod listings, i.e. verifiable places an author publishes this artifact's source/releases.
     */
    private static final Pattern SOURCE_PATTERN = Pattern.compile(
            "(?i)(?:https?://)?(?:[\\w-]+\\.)*"
                    + "(?:github\\.com|githubusercontent\\.com|gitlab\\.com|bitbucket\\.org|codeberg\\.org"
                    + "|sourceforge\\.net|modrinth\\.com|curseforge\\.com|spigotmc\\.org|hangar\\.papermc\\.io"
                    + "|papermc\\.io|dev\\.bukkit\\.org|polymart\\.org|builtbybit\\.com)"
                    + "(?:/[\\w./_~%#?=&+@:-]*)?");

    /** Descriptor / manifest entries whose declared homepage, source or issues link is authoritative. */
    private static final List<String> METADATA_RESOURCES = List.of(
            "plugin.yml", "paper-plugin.yml", "bungee.yml", "velocity-plugin.json",
            "fabric.mod.json", "quilt.mod.json", "pack.mcmeta",
            "META-INF/mods.toml", "META-INF/neoforge.mods.toml", "META-INF/MANIFEST.MF");

    /**
     * Source verification is not yet automated (we don't fetch the repo or check a signature), but we
     * <em>do</em> look at what the artifact declares about itself. If its descriptor, manifest or
     * embedded strings point at a public repository or an official listing, that link is surfaced as
     * informational provenance; otherwise the report carries the explicit "no source was found"
     * notice so a clean static scan is never mistaken for a guarantee.
     */
    private void addProvenanceNotice(AnalysisContext ctx) {
        Set<String> sources = findSourceLinks(ctx);
        if (sources.isEmpty()) {
            ctx.add(Finding.builder("PROVENANCE_UNVERIFIED", Category.PROVENANCE, Severity.LOW)
                    .title("No source link found")
                    .description("No GitHub repository, official listing or signed release was found in this file's "
                            + "metadata, and none was verified. A clean static scan is not a guarantee of safety.")
                    .recommendation("Prefer plugins from official, verifiable sources (a public repo or a known listing).")
                    .scoreImpact(5)
                    .build());
            return;
        }

        String joined = String.join(", ", sources);
        ctx.add(Finding.builder("PROVENANCE_SOURCE_FOUND", Category.PROVENANCE, Severity.INFO)
                .title("Source link found in metadata")
                .description("This file declares a public source repository or official listing: " + joined + ". "
                        + "PluginGuard found the link but has not verified that the published source matches this "
                        + "exact build, nor that the release is signed — a link is not proof the binary is the same code.")
                .recommendation("Open the link, confirm it is the official project, and check the version/commit "
                        + "matches the file you are installing.")
                .evidence(joined)
                .scoreImpact(0)
                .build());
    }

    /** Collects distinct source/listing URLs declared in the artifact's metadata or strings (capped). */
    private Set<String> findSourceLinks(AnalysisContext ctx) {
        Set<String> found = new LinkedHashSet<>();

        // 1. Declared metadata (descriptors + manifest) is the most authoritative place for a homepage.
        for (ResourceFile resource : ctx.jar().resources()) {
            if (resource.nested()) {
                continue; // a bundled library's own repo is not this artifact's provenance
            }
            String name = resource.name();
            boolean isMetadata = METADATA_RESOURCES.stream().anyMatch(name::equalsIgnoreCase);
            if (isMetadata) {
                collectSourceUrls(resource.text(), found);
            }
        }

        // 2. URLs the string/IOC pass already surfaced (covers links embedded in code, not just descriptors).
        for (String indicator : ctx.network()) {
            collectSourceUrls(indicator, found);
        }

        return found;
    }

    private void collectSourceUrls(String text, Set<String> into) {
        if (text == null || text.isBlank() || into.size() >= 6) {
            return;
        }
        Matcher m = SOURCE_PATTERN.matcher(text);
        while (m.find() && into.size() < 6) {
            String url = m.group().replaceAll("[.,);\\]\"']+$", "");
            // De-duplicate case-insensitively while keeping the first-seen form for display.
            String key = url.toLowerCase(Locale.ROOT);
            if (into.stream().noneMatch(u -> u.toLowerCase(Locale.ROOT).equals(key))) {
                into.add(url);
            }
        }
    }
}
