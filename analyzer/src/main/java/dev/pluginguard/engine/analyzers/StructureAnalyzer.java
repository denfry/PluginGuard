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

        // Nested JARs (shaded libs are common, but they are not recursively analyzed in this version).
        for (String nested : jar.nestedJars()) {
            ctx.add(Finding.builder("STRUCTURE_NESTED_JAR", Category.STRUCTURE, Severity.LOW)
                    .title("Nested JAR found")
                    .description("The archive bundles another JAR ('" + nested + "'). This is common for shaded "
                            + "libraries, but its contents are not deeply analyzed in this version.")
                    .recommendation("If you don't recognise the bundled library, review it separately.")
                    .location(nested)
                    .evidence(nested)
                    .scoreImpact(5)
                    .build());
        }

        // Java-agent manifest capability.
        jar.resource("META-INF/MANIFEST.MF").ifPresent(mf -> checkManifest(ctx, mf));

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
        }
    }
}
