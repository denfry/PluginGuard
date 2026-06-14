package dev.pluginguard.engine.analyzers;

import dev.pluginguard.engine.AnalysisContext;
import dev.pluginguard.engine.Analyzer;
import dev.pluginguard.engine.model.Category;
import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.JarEntryInfo;
import dev.pluginguard.engine.model.JarModel;
import dev.pluginguard.engine.model.ResourceFile;
import dev.pluginguard.engine.model.Severity;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Inspects the container itself: is it a real JAR, does it carry native executables, nested JARs,
 * a Java-agent manifest, or signs of a zip-bomb.
 */
@Component
@Order(10)
public class StructureAnalyzer implements Analyzer {

    /** Native / executable / script extensions that have no business inside a plugin JAR. */
    private static final Set<String> NATIVE_EXTENSIONS = Set.of(
            ".dll", ".so", ".dylib", ".jnilib", ".exe", ".bat", ".cmd",
            ".ps1", ".sh", ".scr", ".msi", ".com");

    /** Manifest attributes that turn a JAR into a JVM agent (can rewrite/instrument any class). */
    private static final List<String> AGENT_MANIFEST_KEYS = List.of(
            "premain-class", "agent-class", "launcher-agent-class");

    @Override
    public String name() {
        return "structure";
    }

    @Override
    public void analyze(AnalysisContext ctx) {
        JarModel jar = ctx.jar();

        if (!jar.validZip()) {
            ctx.add(Finding.builder("STRUCTURE_NOT_A_JAR", Category.STRUCTURE, Severity.HIGH)
                    .title("File is not a valid JAR archive")
                    .description("The uploaded file does not start with the ZIP signature, so it is not a real "
                            + "plugin JAR. It may be a renamed or corrupted file.")
                    .recommendation("Do not install this file. Re-download the plugin from a trusted source.")
                    .evidence(jar.fileName())
                    .scoreImpact(35)
                    .build());
            return;
        }

        if (jar.classes().isEmpty()) {
            ctx.add(Finding.builder("STRUCTURE_NO_CLASSES", Category.STRUCTURE, Severity.LOW)
                    .title("Archive contains no Java classes")
                    .description("No .class files were found. This is unusual for a working plugin.")
                    .recommendation("Verify this is actually a plugin and not a resource pack or data archive.")
                    .scoreImpact(5)
                    .build());
        }

        // Native / executable payloads.
        for (JarEntryInfo entry : jar.entries()) {
            String lower = entry.name().toLowerCase(Locale.ROOT);
            for (String ext : NATIVE_EXTENSIONS) {
                if (lower.endsWith(ext)) {
                    ctx.add(Finding.builder("STRUCTURE_NATIVE_FILE", Category.NATIVE, Severity.HIGH)
                            .title("Native or executable file bundled in JAR")
                            .description("The archive contains '" + entry.name() + "', a native/executable file. "
                                    + "Plugins can load native code that runs outside the JVM's protections, which "
                                    + "is a strong red flag for malware.")
                            .recommendation("Treat as high risk. Legitimate plugins almost never ship .exe/.dll/.so files.")
                            .location(entry.name())
                            .evidence(entry.name())
                            .scoreImpact(30)
                            .build());
                    break;
                }
            }
        }

        // Nested JARs (shaded libs are common). Their contents are unpacked and analyzed recursively
        // by the JarLoader, so any findings inside them are attributed with the jar-chain path.
        for (String nested : jar.nestedJars()) {
            ctx.add(Finding.builder("STRUCTURE_NESTED_JAR", Category.STRUCTURE, Severity.INFO)
                    .title("Nested JAR found")
                    .description("The archive bundles another JAR ('" + nested + "'). This is common for shaded "
                            + "libraries; its classes were unpacked and analyzed recursively, and any findings inside "
                            + "it are labelled with the nested path.")
                    .recommendation("If you don't recognise the bundled library, review its findings below.")
                    .location(nested)
                    .evidence(nested)
                    .scoreImpact(0)
                    .build());
        }

        // Zip-slip / path traversal: entry names that escape the extraction directory. Harmless for a
        // server that loads a plugin in place, but resource/data packs and mods are unpacked by many
        // tools, and a "../" entry can overwrite files outside the target folder.
        checkPathTraversal(ctx, jar);

        // Java-agent manifest capability.
        jar.resource("META-INF/MANIFEST.MF").ifPresent(mf -> checkManifest(ctx, mf));

        // Central-directory / stream desync: entries hidden from one view or the other.
        for (String anomaly : jar.zipAnomalies()) {
            ctx.add(Finding.builder("STRUCTURE_ZIP_ANOMALY", Category.STRUCTURE, Severity.HIGH)
                    .title("ZIP structure is inconsistent (hidden entries)")
                    .description(anomaly + " A mismatch between the ZIP central directory and the actual stream is a "
                            + "deliberate trick to hide code from inspection tools while the server still loads it.")
                    .recommendation("Treat as hostile. A legitimate plugin's archive is internally consistent.")
                    .evidence(anomaly.length() <= 160 ? anomaly : anomaly.substring(0, 157) + "...")
                    .scoreImpact(30)
                    .build());
        }

        // Zip-bomb signals surfaced by the loader's guards.
        for (String note : jar.guardNotes()) {
            String n = note.toLowerCase(Locale.ROOT);
            if (n.contains("compression ratio") || n.contains("zip-bomb")) {
                ctx.add(Finding.builder("STRUCTURE_ZIP_BOMB", Category.STRUCTURE, Severity.MEDIUM)
                        .title("Possible zip-bomb behaviour")
                        .description("An entry decompressed to a suspiciously large size relative to its stored size.")
                        .recommendation("Be cautious — this can be used to exhaust server disk or memory.")
                        .evidence(note)
                        .scoreImpact(15)
                        .build());
            }
        }
    }

    /** Flags entries whose path escapes the extraction root ({@code ../}, absolute or drive-qualified). */
    private void checkPathTraversal(AnalysisContext ctx, JarModel jar) {
        List<String> offending = new ArrayList<>();
        for (JarEntryInfo entry : jar.entries()) {
            String name = entry.name();
            // Compare on the path within its own archive (after any nested "lib.jar!/" prefix).
            int sep = name.lastIndexOf("!/");
            String bare = sep >= 0 ? name.substring(sep + 2) : name;
            if (bare.contains("../") || bare.contains("..\\")
                    || bare.startsWith("/") || bare.startsWith("\\")
                    || bare.matches("(?i)^[a-z]:[\\\\/].*")) {
                offending.add(name);
            }
        }
        if (offending.isEmpty()) {
            return;
        }
        int limit = Math.min(offending.size(), 5);
        String examples = String.join(", ", offending.subList(0, limit));
        ctx.add(Finding.builder("STRUCTURE_PATH_TRAVERSAL", Category.STRUCTURE, Severity.HIGH)
                .title("Archive entry escapes its folder (zip-slip)")
                .description("The archive contains " + offending.size() + " entry path(s) that point outside the "
                        + "extraction directory (e.g. '../' or an absolute path): " + examples
                        + (offending.size() > limit ? ", …" : "") + ". When unpacked by a tool that does not sanitise "
                        + "paths, such an entry can overwrite files elsewhere on disk — the zip-slip attack.")
                .recommendation("Treat as hostile. Legitimate plugins/mods/packs never need to write outside their own tree.")
                .evidence(examples.length() <= 160 ? examples : examples.substring(0, 157) + "...")
                .scoreImpact(28)
                .build());
    }

    private void checkManifest(AnalysisContext ctx, ResourceFile manifest) {
        String text = manifest.text();
        for (String line : text.split("\\r?\\n")) {
            int colon = line.indexOf(':');
            if (colon <= 0) {
                continue;
            }
            String key = line.substring(0, colon).trim().toLowerCase(Locale.ROOT);
            String value = line.substring(colon + 1).trim();
            if (AGENT_MANIFEST_KEYS.contains(key)) {
                ctx.add(Finding.builder("STRUCTURE_JAVA_AGENT", Category.CLASS_LOADING, Severity.HIGH)
                        .title("JAR declares a Java agent")
                        .description("The manifest declares '" + key + "', which lets the JAR instrument or rewrite "
                                + "other classes at runtime. This is not normal for a Bukkit/Paper plugin.")
                        .recommendation("Investigate why this plugin needs agent/instrumentation capabilities.")
                        .location("META-INF/MANIFEST.MF")
                        .evidence(key + ": " + value)
                        .scoreImpact(25)
                        .build());
            }
            if (key.equals("class-path") && !value.isBlank()) {
                boolean external = value.contains("http://") || value.contains("https://")
                        || value.contains("..") || value.contains("/") || value.contains("\\");
                ctx.add(Finding.builder("STRUCTURE_MANIFEST_CLASSPATH",
                                Category.SUPPLY_CHAIN, external ? Severity.MEDIUM : Severity.LOW)
                        .title("Manifest declares an external Class-Path")
                        .description("The manifest sets 'Class-Path: " + value + "'. This makes the JVM load classes "
                                + "from other locations on disk at runtime" + (external
                                ? ", and the entries point outside the JAR — code outside this file would run."
                                : ".") + " Plugin classloading is normally handled by the server, not the manifest.")
                        .recommendation("Confirm why the plugin pulls classes in via the manifest Class-Path.")
                        .location("META-INF/MANIFEST.MF")
                        .evidence("Class-Path: " + value)
                        .scoreImpact(external ? 14 : 6)
                        .build());
            }
        }
    }
}
