package dev.pluginguard.engine.analyzers;

import dev.pluginguard.engine.AnalysisContext;
import dev.pluginguard.engine.Analyzer;
import dev.pluginguard.engine.model.Category;
import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.ResourceFile;
import dev.pluginguard.engine.model.Severity;
import dev.pluginguard.engine.util.Magic;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.Set;

/**
 * Inspects the <em>raw bytes</em> of every resource — independent of its filename — to catch
 * executables, classes or archives disguised under an innocent extension (a {@code .png} that is
 * really a Java class, a {@code .dat} that is really a Windows {@code .exe}). Also runs an entropy
 * check to flag resources that look encrypted/packed.
 */
@Component
@Order(15)
public class EmbeddedPayloadAnalyzer implements Analyzer {

    private static final double HIGH_ENTROPY_THRESHOLD = 7.3;
    private static final int MIN_ENTROPY_SIZE = 2048;
    private static final int ENTROPY_SAMPLE = 262_144;
    private static final int MAX_FINDINGS = 30;

    /** Extensions whose content is legitimately compressed/encrypted, so high entropy is expected. */
    private static final Set<String> COMPRESSED_EXTENSIONS = Set.of(
            ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico",
            ".zip", ".jar", ".war", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar",
            ".ogg", ".mp3", ".mp4", ".webm", ".wav", ".flac",
            ".woff", ".woff2", ".pdf", ".jks", ".keystore", ".p12", ".pfx");

    /** Extensions for which an executable/native signature is already expected (handled elsewhere). */
    private static final Set<String> EXECUTABLE_EXTENSIONS = Set.of(
            ".class", ".jar", ".zip", ".war", ".dll", ".so", ".dylib", ".jnilib",
            ".exe", ".bin", ".com", ".scr", ".msi");

    @Override
    public String name() {
        return "embedded-payload";
    }

    @Override
    public void analyze(AnalysisContext ctx) {
        int emitted = 0;
        for (ResourceFile res : ctx.jar().resources()) {
            if (emitted >= MAX_FINDINGS) {
                break;
            }
            byte[] bytes = res.bytes();
            String ext = extensionOf(res.name());
            Magic.Kind kind = Magic.detect(bytes);

            if (kind != Magic.Kind.NONE && !signatureExpected(ext, kind)) {
                emitDisguised(ctx, res, kind);
                emitted++;
                continue;
            }

            if (isHighEntropyPayload(bytes, ext)) {
                ctx.add(Finding.builder("EMBEDDED_HIGH_ENTROPY", Category.STRING_IOC, Severity.LOW)
                        .title("High-entropy resource (possibly encrypted/packed)")
                        .description("Resource '" + res.displayName() + "' has very high entropy ("
                                + String.format(Locale.ROOT, "%.2f", Magic.entropy(sample(bytes))) + "/8.0) and an extension "
                                + "that is not normally compressed. This can simply be data, but it is also what an "
                                + "encrypted payload looks like before it is decrypted at runtime.")
                        .recommendation("Worth a look if the plugin also decrypts data or loads classes.")
                        .location(res.displayName())
                        .evidence("entropy " + String.format(Locale.ROOT, "%.2f", Magic.entropy(sample(bytes))))
                        .nestedPath(res.nested() ? res.container() : null)
                        .scoreImpact(5)
                        .build());
                emitted++;
            }
        }
    }

    private void emitDisguised(AnalysisContext ctx, ResourceFile res, Magic.Kind kind) {
        Category category;
        Severity severity;
        int impact;
        switch (kind) {
            case JAVA_CLASS -> {
                category = Category.CLASS_LOADING;
                severity = Severity.HIGH;
                impact = 30;
            }
            case WINDOWS_PE, ELF_BINARY, MACH_O -> {
                category = Category.NATIVE;
                severity = Severity.CRITICAL;
                impact = 45;
            }
            default -> { // ZIP / GZIP disguised under a non-archive extension
                category = Category.STRUCTURE;
                severity = Severity.MEDIUM;
                impact = 18;
            }
        }
        ctx.add(Finding.builder("EMBEDDED_DISGUISED_PAYLOAD", category, severity)
                .title("File contents do not match its extension")
                .description("Resource '" + res.displayName() + "' is named like an ordinary file but its bytes are a "
                        + kind.label() + ". Disguising executable content under a harmless extension is a deliberate "
                        + "evasion technique.")
                .recommendation("Treat as suspicious; legitimate resources match their declared type.")
                .location(res.displayName())
                .evidence(kind.label())
                .nestedPath(res.nested() ? res.container() : null)
                .scoreImpact(impact)
                .build());
    }

    private boolean signatureExpected(String ext, Magic.Kind kind) {
        if (kind == Magic.Kind.ZIP_ARCHIVE || kind == Magic.Kind.GZIP) {
            return EXECUTABLE_EXTENSIONS.contains(ext) || COMPRESSED_EXTENSIONS.contains(ext);
        }
        // Class / native signatures are only "expected" for executable-type extensions.
        return EXECUTABLE_EXTENSIONS.contains(ext);
    }

    private boolean isHighEntropyPayload(byte[] bytes, String ext) {
        if (bytes.length < MIN_ENTROPY_SIZE || COMPRESSED_EXTENSIONS.contains(ext)) {
            return false;
        }
        return Magic.entropy(sample(bytes)) >= HIGH_ENTROPY_THRESHOLD;
    }

    private static byte[] sample(byte[] bytes) {
        if (bytes.length <= ENTROPY_SAMPLE) {
            return bytes;
        }
        byte[] out = new byte[ENTROPY_SAMPLE];
        System.arraycopy(bytes, 0, out, 0, ENTROPY_SAMPLE);
        return out;
    }

    private static String extensionOf(String name) {
        String lower = name.toLowerCase(Locale.ROOT);
        int slash = Math.max(lower.lastIndexOf('/'), lower.lastIndexOf('\\'));
        int dot = lower.lastIndexOf('.');
        return dot > slash ? lower.substring(dot) : "";
    }
}
