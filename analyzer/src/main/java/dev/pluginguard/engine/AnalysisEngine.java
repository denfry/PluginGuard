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

import java.time.Instant;
import java.util.Comparator;
import java.util.List;

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
                null); // dynamic sandbox section is attached later by SandboxService, if enabled
    }

    /**
     * Until source/signature verification is implemented, every report carries an explicit notice
     * that provenance was not checked, so a clean static scan is never mistaken for a guarantee.
     */
    private void addProvenanceNotice(AnalysisContext ctx) {
        ctx.add(Finding.builder("PROVENANCE_UNVERIFIED", Category.PROVENANCE, Severity.LOW)
                .title("Source not verified")
                .description("No GitHub repository, signed release or reproducible build was checked for this file. "
                        + "A clean static scan is not a guarantee of safety.")
                .recommendation("Prefer plugins from official, verifiable sources.")
                .scoreImpact(5)
                .build());
    }
}
