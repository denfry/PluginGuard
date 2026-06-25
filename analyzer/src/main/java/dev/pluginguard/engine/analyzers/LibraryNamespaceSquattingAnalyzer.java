package dev.pluginguard.engine.analyzers;

import dev.pluginguard.engine.AnalysisContext;
import dev.pluginguard.engine.Analyzer;
import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.model.Category;
import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.Severity;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Generic detector for <strong>library-namespace squatting</strong>: a class planted inside a
 * trusted third-party library's package so it blends in with the artifact's shaded dependencies.
 *
 * <p>This is the technique behind several Minecraft plugin backdoors — the Artemka and bStats.jar
 * injectors hide under JetBrains' {@code org.intellij.lang.annotations} namespace, the chbk packet
 * backdoor squats in {@code org.apache.commons.lang3}, and HostFlow plants classes in
 * {@code javassist/}. Unlike the per-family {@link MalwareSignatureAnalyzer} indicators, this rule
 * keys on the <em>technique</em>, so it still fires when a known family is repacked with renamed
 * classes — and catches unnamed malware that uses the same trick.
 *
 * <p><strong>Two low-false-positive modes per watched namespace:</strong>
 * <ul>
 *   <li><b>Allow-list</b> — for an annotations-only namespace where a plugin never legitimately
 *       <em>defines</em> a class: any class whose simple name isn't a known annotation is squatting.</li>
 *   <li><b>Anchor</b> — for a monolithic library that always ships together: if the artifact defines
 *       classes under the namespace but is <em>missing</em> the library's anchor classes (e.g. Gson,
 *       {@code StringUtils}, {@code ClassPool}), the library isn't really there — the classes were
 *       planted. A genuine shaded copy always brings its anchors, so it is never flagged.</li>
 * </ul>
 *
 * <p>Only monolithic libraries (which cannot be partially shaded into a state lacking their anchors)
 * are watched in anchor mode, keeping false positives near zero. Read-only: it inspects pre-computed
 * class names and never loads a class.
 */
@Component
@Order(46)
public class LibraryNamespaceSquattingAnalyzer implements Analyzer {

    /**
     * A watched library namespace.
     *
     * @param prefix      internal-name prefix with a trailing {@code /}
     * @param allowed     allow-list mode: lowercase simple names that legitimately live under the prefix;
     *                    {@code null} ⇒ anchor mode
     * @param anchors     anchor mode: full internal names whose presence proves the real library is shaded
     * @param library     human-readable library name for the finding text
     */
    private record Watch(String prefix, Set<String> allowed, Set<String> anchors, String library) {
        static Watch allowList(String prefix, String library, String... allowed) {
            return new Watch(prefix, Set.of(allowed), Set.of(), library);
        }
        static Watch anchored(String prefix, String library, String... anchors) {
            return new Watch(prefix, null, Set.of(anchors), library);
        }
        boolean isAnchorMode() {
            return allowed == null;
        }
    }

    private static final List<Watch> WATCHED = List.of(
            // Annotations-only: no plugin defines a class here. Abused by Artemka + bStats.jar.
            Watch.allowList("org/intellij/lang/annotations/", "JetBrains annotations",
                    "flow", "identifier", "jdkconstants", "language", "magicconstant",
                    "pattern", "printformat", "regexp", "subst"),
            // Monolithic libraries — anchor classes that any genuine shaded copy always contains.
            Watch.anchored("org/apache/commons/lang3/", "Apache Commons Lang",
                    "org/apache/commons/lang3/StringUtils", "org/apache/commons/lang3/ObjectUtils"),
            Watch.anchored("javassist/", "Javassist",
                    "javassist/ClassPool", "javassist/CtClass"),
            Watch.anchored("com/google/gson/", "Gson",
                    "com/google/gson/Gson", "com/google/gson/JsonElement"),
            Watch.anchored("com/google/common/", "Guava",
                    "com/google/common/collect/ImmutableList", "com/google/common/base/Preconditions"),
            Watch.anchored("org/yaml/snakeyaml/", "SnakeYAML",
                    "org/yaml/snakeyaml/Yaml"),
            Watch.anchored("org/json/", "org.json",
                    "org/json/JSONObject", "org/json/JSONArray"));

    @Override
    public String name() {
        return "namespace-squatting";
    }

    @Override
    public void analyze(AnalysisContext ctx) {
        Set<String> defined = new HashSet<>();
        for (ClassScan scan : ctx.classScans()) {
            if (scan.internalName() != null) {
                defined.add(scan.internalName());
            }
        }

        for (Watch watch : WATCHED) {
            List<ClassScan> offenders = offendersFor(ctx, watch, defined);
            if (offenders.isEmpty()) {
                continue;
            }
            ClassScan first = offenders.get(0);
            String namespace = watch.prefix().substring(0, watch.prefix().length() - 1).replace('/', '.');
            ctx.add(Finding.builder("STRUCTURE_NAMESPACE_SQUATTING", Category.STRUCTURE, Severity.HIGH)
                    .title("Class planted inside a third-party library namespace")
                    .description(offenders.size() + " class(es) live under the " + namespace + " namespace ("
                            + watch.library() + ") but are not part of that library. Planting classes inside a "
                            + "trusted library's package is a concealment technique used by Minecraft plugin "
                            + "backdoors (e.g. Artemka, bStats.jar, chbk, HostFlow) to blend malicious code in "
                            + "with shaded dependencies.")
                    .recommendation("Treat as malicious unless you can account for these classes. A legitimate "
                            + "plugin never defines its own classes inside another project's package.")
                    .location(first.displayName())
                    .evidence(truncate(offenders))
                    .scoreImpact(45)
                    .build());
        }
    }

    private static List<ClassScan> offendersFor(AnalysisContext ctx, Watch watch, Set<String> defined) {
        List<ClassScan> underPrefix = new ArrayList<>();
        for (ClassScan scan : ctx.classScans()) {
            String internal = scan.internalName();
            if (internal != null && internal.startsWith(watch.prefix())
                    && !internal.substring(watch.prefix().length()).isEmpty()) {
                underPrefix.add(scan);
            }
        }
        if (underPrefix.isEmpty()) {
            return List.of();
        }
        if (watch.isAnchorMode()) {
            // The real library is shaded iff at least one anchor class is present → not squatting.
            boolean anchorPresent = watch.anchors().stream().anyMatch(defined::contains);
            if (anchorPresent) {
                return List.of();
            }
            return underPrefix;
        }
        // Allow-list mode: flag classes whose top-level simple name isn't a known member.
        List<ClassScan> offenders = new ArrayList<>();
        for (ClassScan scan : underPrefix) {
            String simple = topLevelSimpleName(scan.internalName().substring(watch.prefix().length()));
            if (!watch.allowed().contains(simple.toLowerCase(Locale.ROOT))) {
                offenders.add(scan);
            }
        }
        return offenders;
    }

    /** Top-level type name: the segment before the first {@code /} (subpackage) or {@code $} (inner class). */
    private static String topLevelSimpleName(String remainder) {
        int slash = remainder.indexOf('/');
        String head = slash >= 0 ? remainder.substring(0, slash) : remainder;
        int dollar = head.indexOf('$');
        return dollar >= 0 ? head.substring(0, dollar) : head;
    }

    private static String truncate(List<ClassScan> offenders) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < offenders.size() && i < 5; i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append(offenders.get(i).dottedName());
        }
        if (offenders.size() > 5) {
            sb.append(", … (+").append(offenders.size() - 5).append(" more)");
        }
        return sb.toString();
    }
}
