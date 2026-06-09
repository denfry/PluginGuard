package dev.pluginguard.engine.analyzers;

import dev.pluginguard.engine.AnalysisContext;
import dev.pluginguard.engine.Analyzer;
import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.bytecode.ClassScanner;
import dev.pluginguard.engine.bytecode.Invocation;
import dev.pluginguard.engine.model.Category;
import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.ResourceFile;
import dev.pluginguard.engine.model.Severity;
import dev.pluginguard.engine.util.Magic;
import dev.pluginguard.engine.util.PayloadDecoder;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Decode-and-rescan. Finds encoded blobs (base64 / hex, optionally single-byte XOR) in class
 * constant pools and text resources, decodes them within strict size limits, and inspects the
 * decoded bytes for the things malware tries to hide there: an embedded Java class
 * ({@code CAFEBABE}) — which is fed back through the ASM scanner — an embedded archive or native
 * executable, or hidden URLs / shell commands.
 */
@Component
@Order(45)
public class PayloadDecoderAnalyzer implements Analyzer {

    /** Cap each decoded blob and bound how many candidates we examine, to avoid a decompress-bomb. */
    private static final int MAX_DECODED_BYTES = 1024 * 1024;
    private static final int MAX_CANDIDATES = 400;
    private static final int MAX_XOR_CANDIDATE_LENGTH = 60_000;
    private static final int MAX_EMBEDDED_RESCANS = 8;
    private static final int MAX_FINDINGS_PER_RULE = 15;

    /** Strong indicators that decoded *text* is a hidden payload, not just data. */
    private static final List<String> TEXT_IOCS = List.of(
            "http://", "https://", "cmd.exe", "powershell", "/bin/sh", "/bin/bash",
            "certutil", "discord.com/api/webhooks", "api.telegram.org");

    /** Owners worth calling out when an embedded class is decoded and rescanned. */
    private static final Set<String> EMBEDDED_DANGEROUS_OWNERS = Set.of(
            "java/lang/Runtime", "java/lang/ProcessBuilder", "java/lang/ClassLoader",
            "java/net/URLClassLoader", "javax/script/ScriptEngineManager", "javax/naming/InitialContext");

    @Override
    public String name() {
        return "payload-decoder";
    }

    @Override
    public void analyze(AnalysisContext ctx) {
        State state = new State();

        for (ClassScan scan : ctx.classScans()) {
            for (String s : scan.stringConstants()) {
                if (state.exhausted()) {
                    return;
                }
                examine(ctx, state, s, scan.displayName(), scan.nestedPath());
            }
        }
        for (ResourceFile res : ctx.jar().resources()) {
            if (state.exhausted()) {
                return;
            }
            if (looksTextual(res)) {
                for (String line : res.text().split("\\r?\\n")) {
                    examine(ctx, state, line, res.displayName(), res.nested() ? res.container() : null);
                }
            }
        }
    }

    private void examine(AnalysisContext ctx, State state, String s, String location, String nestedPath) {
        if (s == null || s.length() < PayloadDecoder.MIN_CANDIDATE_LENGTH) {
            return;
        }
        state.candidates++;
        boolean tryXor = s.length() <= MAX_XOR_CANDIDATE_LENGTH;
        for (PayloadDecoder.Decoded decoded : PayloadDecoder.decode(s, MAX_DECODED_BYTES, tryXor)) {
            inspect(ctx, state, decoded, location, nestedPath);
        }
    }

    private void inspect(AnalysisContext ctx, State state, PayloadDecoder.Decoded decoded,
                         String location, String nestedPath) {
        byte[] bytes = decoded.bytes();
        Magic.Kind kind = Magic.detect(bytes);
        boolean xor = decoded.method().contains("xor");

        switch (kind) {
            case JAVA_CLASS -> {
                String extra = state.rescans < MAX_EMBEDDED_RESCANS ? rescanEmbeddedClass(bytes, ++state.rescans) : "";
                emit(ctx, state, Finding.builder("DECODE_EMBEDDED_CLASS", Category.CLASS_LOADING, Severity.CRITICAL)
                        .title("Hidden Java class inside an encoded blob")
                        .description("A " + decoded.method() + "-encoded string decodes to a Java class (CAFEBABE). Shipping "
                                + "executable bytecode inside a string is a deliberate way to smuggle code past inspection"
                                + (xor ? ", and it was additionally XOR-obfuscated" : "") + "." + extra)
                        .recommendation("Treat as malicious unless the plugin clearly documents this mechanism.")
                        .location(location).evidence(decoded.method() + " → CAFEBABE")
                        .nestedPath(nestedPath).scoreImpact(55).build());
            }
            case ZIP_ARCHIVE -> emit(ctx, state, Finding.builder("DECODE_EMBEDDED_ARCHIVE", Category.CLASS_LOADING, Severity.HIGH)
                    .title("Hidden archive inside an encoded blob")
                    .description("A " + decoded.method() + "-encoded string decodes to a ZIP/JAR archive. Bundling a hidden "
                            + "archive this way is commonly used to unpack and load code at runtime.")
                    .recommendation("Investigate what the embedded archive contains and when it is unpacked.")
                    .location(location).evidence(decoded.method() + " → PK\\x03\\x04")
                    .nestedPath(nestedPath).scoreImpact(35).build());
            case WINDOWS_PE, ELF_BINARY, MACH_O -> emit(ctx, state, Finding.builder("DECODE_EMBEDDED_NATIVE", Category.NATIVE, Severity.CRITICAL)
                    .title("Hidden native executable inside an encoded blob")
                    .description("A " + decoded.method() + "-encoded string decodes to a native executable (" + kind.label()
                            + "). This is a dropper pattern: a real OS binary smuggled inside the plugin.")
                    .recommendation("Treat as malicious. Plugins have no reason to embed native executables in strings.")
                    .location(location).evidence(decoded.method() + " → " + kind.label())
                    .nestedPath(nestedPath).scoreImpact(60).build());
            default -> inspectAsText(ctx, state, decoded, bytes, location, nestedPath, xor);
        }
    }

    private void inspectAsText(AnalysisContext ctx, State state, PayloadDecoder.Decoded decoded, byte[] bytes,
                               String location, String nestedPath, boolean xor) {
        if (xor) {
            return; // XOR results without a known magic are almost always noise.
        }
        if (!mostlyPrintable(bytes)) {
            return;
        }
        String text = new String(bytes, StandardCharsets.UTF_8).toLowerCase(Locale.ROOT);
        for (String ioc : TEXT_IOCS) {
            if (text.contains(ioc)) {
                emit(ctx, state, Finding.builder("DECODE_HIDDEN_IOC", Category.STRING_IOC, Severity.HIGH)
                        .title("Hidden indicator inside an encoded string")
                        .description("A " + decoded.method() + "-encoded string decodes to text containing '" + ioc
                                + "'. Hiding a URL or shell command behind encoding is a common way to conceal "
                                + "command-and-control or download endpoints from a casual look.")
                        .recommendation("Decode and review the full string; confirm where it points.")
                        .location(location).evidence(decoded.method() + " → " + ioc)
                        .nestedPath(nestedPath).scoreImpact(24).build());
                return;
            }
        }
    }

    /** Rescans decoded class bytes with ASM and summarises any dangerous calls it would make. */
    private String rescanEmbeddedClass(byte[] classBytes, int index) {
        ClassScan scan = ClassScanner.scanBytes("embedded$" + index, classBytes, "");
        if (!scan.parsed()) {
            return "";
        }
        Set<String> dangerous = new HashSet<>();
        for (Invocation inv : scan.invocations()) {
            if (EMBEDDED_DANGEROUS_OWNERS.contains(inv.owner())) {
                dangerous.add(inv.ownerDotted() + "." + inv.name() + "()");
            }
        }
        String name = scan.dottedName();
        String base = " The decoded class is '" + name + "'.";
        return dangerous.isEmpty() ? base
                : base + " It references: " + String.join(", ", dangerous) + ".";
    }

    private void emit(AnalysisContext ctx, State state, Finding f) {
        String key = f.ruleId() + "|" + f.location() + "|" + f.evidence();
        if (!state.seen.add(key)) {
            return;
        }
        if (state.perRule.merge(f.ruleId(), 1, Integer::sum) > MAX_FINDINGS_PER_RULE) {
            return;
        }
        ctx.add(f);
    }

    private boolean looksTextual(ResourceFile res) {
        String lower = res.name().toLowerCase(Locale.ROOT);
        return lower.endsWith(".yml") || lower.endsWith(".yaml") || lower.endsWith(".json")
                || lower.endsWith(".txt") || lower.endsWith(".properties") || lower.endsWith(".conf")
                || lower.endsWith(".cfg") || lower.endsWith(".ini") || lower.endsWith(".xml")
                || lower.endsWith(".js") || lower.endsWith(".csv") || lower.endsWith(".env");
    }

    private static boolean mostlyPrintable(byte[] b) {
        if (b.length == 0) {
            return false;
        }
        int printable = 0;
        int limit = Math.min(b.length, 4096);
        for (int i = 0; i < limit; i++) {
            int c = b[i] & 0xFF;
            if (c == 9 || c == 10 || c == 13 || (c >= 32 && c < 127)) {
                printable++;
            }
        }
        return printable / (double) limit > 0.85;
    }

    /** Mutable budget for one analysis run. */
    private static final class State {
        final Set<String> seen = new HashSet<>();
        final java.util.Map<String, Integer> perRule = new java.util.HashMap<>();
        int candidates = 0;
        int rescans = 0;

        boolean exhausted() {
            return candidates >= MAX_CANDIDATES;
        }
    }
}
