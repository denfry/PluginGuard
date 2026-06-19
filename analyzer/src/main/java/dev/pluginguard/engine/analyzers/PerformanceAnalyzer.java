package dev.pluginguard.engine.analyzers;

import dev.pluginguard.engine.AnalysisContext;
import dev.pluginguard.engine.Analyzer;
import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.bytecode.Invocation;
import dev.pluginguard.engine.model.Category;
import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.Severity;
import dev.pluginguard.engine.perf.BukkitHotPathModel;
import dev.pluginguard.engine.perf.CallGraph;
import dev.pluginguard.engine.perf.FabricHotPathModel;
import dev.pluginguard.engine.perf.ForgeHotPathModel;
import dev.pluginguard.engine.perf.Heat;
import dev.pluginguard.engine.perf.HotEntrypoint;
import dev.pluginguard.engine.perf.HotPathModel;
import dev.pluginguard.engine.perf.PerfSinkTable;
import dev.pluginguard.engine.perf.PerfSinkTable.PerfSink;
import dev.pluginguard.engine.perf.PerfSinkTable.SinkWeight;
import dev.pluginguard.engine.perf.ProxyHotPathModel;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;

/**
 * Performance (lag-risk) analysis. Picks the hot-path model for the artifact, builds an intra-jar
 * call graph, marks the methods reachable from hot entrypoints, and reports perf-sensitive sinks
 * found in those reachable methods, scaling severity by sink weight, context heat and call distance
 * (Hybrid C). Also mirrors data-pack lag-loop findings onto the Performance axis.
 *
 * <p>Runs after {@code PackAnalyzer} (@Order 50) so its data-pack findings exist, and before the
 * correlation pass (@Order 1000).
 */
@Component
@Order(70)
public class PerformanceAnalyzer implements Analyzer {

    private static final int MAX_DEPTH = 5;

    private final List<HotPathModel> models = List.of(
            new BukkitHotPathModel(),
            new ForgeHotPathModel(),
            new FabricHotPathModel(),
            new ProxyHotPathModel());

    @Override
    public String name() {
        return "PerformanceAnalyzer";
    }

    @Override
    public void analyze(AnalysisContext ctx) {
        mirrorDataPackLagLoops(ctx);

        List<ClassScan> classes = ctx.classScans();
        if (classes.isEmpty()) {
            return;
        }
        HotPathModel model = models.stream()
                .filter(m -> m.supports(ctx.artifactType()))
                .findFirst().orElse(null);
        if (model == null) {
            return;
        }
        List<HotEntrypoint> entrypoints = model.entrypoints(classes);
        if (entrypoints.isEmpty()) {
            return;
        }

        CallGraph graph = new CallGraph(classes);
        Map<String, CallGraph.Reach> reachable = graph.reachableFrom(entrypoints, MAX_DEPTH);

        for (ClassScan c : classes) {
            for (Invocation inv : c.invocations()) {
                CallGraph.Reach reach = reachable.get(CallGraph.key(inv.callerClass(), inv.callerMethod()));
                if (reach == null) {
                    continue; // not on a hot path — cold-path suppression
                }
                PerfSinkTable.match(inv.owner(), inv.name()).ifPresent(sink ->
                        ctx.add(finding(c, inv, sink, reach)));
            }
        }
    }

    private static Finding finding(ClassScan c, Invocation inv, PerfSink sink, CallGraph.Reach reach) {
        Severity severity = severity(sink, reach);
        String where = inv.callerClass().replace('/', '.') + "#" + inv.callerMethod();
        String distanceNote = reach.distance() == 0
                ? "directly in a hot path"
                : "reachable " + reach.distance() + " call(s) deep from a hot path";
        return Finding.builder("PERF_" + ruleSuffix(inv), Category.PERFORMANCE, severity)
                .title(sink.title())
                .description(sink.title() + " — " + distanceNote
                        + " (context frequency: " + reach.heat().name().toLowerCase() + "). "
                        + "Expensive work on the server thread stalls the tick and lowers TPS under load.")
                .recommendation(sink.recommendation())
                .location(where)
                .evidence(inv.ownerDotted() + "." + inv.name())
                .scoreImpact(scoreImpact(severity))
                .nestedPath(c.nestedPath())
                .build();
    }

    private static String ruleSuffix(Invocation inv) {
        // Stable-ish suffix per sink: last path segment of the owner, uppercased.
        String owner = inv.owner();
        String tail = owner.substring(owner.lastIndexOf('/') + 1).toUpperCase();
        return tail + "_" + inv.name().toUpperCase();
    }

    /**
     * Severity = base(weight) + heatAdjust − distanceDecay, floored at MEDIUM for always-bad sinks,
     * clamped to LOW..CRITICAL.
     */
    private static Severity severity(PerfSink sink, CallGraph.Reach reach) {
        int level = baseLevel(sink.weight());           // LIGHT=1 .. SEVERE=4
        level += switch (reach.heat()) {
            case HOT -> 1;
            case WARM -> 0;
            case COOL -> -1;
        };
        level -= reach.distance() / 2;                  // 0–1 no decay, 2–3 −1, 4–5 −2
        if (sink.alwaysBadOnMainThread()) {
            level = Math.max(level, 2);                 // floor at MEDIUM
        }
        level = Math.max(1, Math.min(4, level));
        return switch (level) {
            case 4 -> Severity.CRITICAL;
            case 3 -> Severity.HIGH;
            case 2 -> Severity.MEDIUM;
            default -> Severity.LOW;
        };
    }

    private static int baseLevel(SinkWeight w) {
        return switch (w) {
            case LIGHT -> 1;
            case MODERATE -> 2;
            case HEAVY -> 3;
            case SEVERE -> 4;
        };
    }

    private static int scoreImpact(Severity severity) {
        return switch (severity) {
            case CRITICAL -> 35;
            case HIGH -> 20;
            case MEDIUM -> 10;
            case LOW -> 5;
            case INFO -> 0;
        };
    }

    /** Mirror existing data-pack lag-loop findings onto the Performance axis (no bytecode involved). */
    private static void mirrorDataPackLagLoops(AnalysisContext ctx) {
        boolean hasLagLoop = ctx.findings().stream().anyMatch(f -> f.ruleId().equals("DP_SELF_RECURSION"));
        if (!hasLagLoop) {
            return;
        }
        ctx.add(Finding.builder("PERF_DATAPACK_LAG_LOOP", Category.PERFORMANCE, Severity.HIGH)
                .title("Self-recursive data-pack function (lag machine)")
                .description("A data-pack function calls itself with no visible terminating guard. Unbounded "
                        + "function recursion runs as fast as the server can manage and will lag or freeze it.")
                .recommendation("Confirm the recursion terminates via a score/condition check before installing.")
                .scoreImpact(20)
                .build());
    }
}
