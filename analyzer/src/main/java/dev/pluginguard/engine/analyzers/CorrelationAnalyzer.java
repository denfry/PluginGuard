package dev.pluginguard.engine.analyzers;

import dev.pluginguard.engine.AnalysisContext;
import dev.pluginguard.engine.Analyzer;
import dev.pluginguard.engine.model.Category;
import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.Severity;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Runs last and raises the alarm on dangerous <em>combinations</em>. Any single capability
 * (networking, reflection, class loading, …) is often legitimate in isolation; what distinguishes
 * malware is the way these capabilities are wired together. This analyzer correlates the findings
 * the other analyzers produced and emits high-severity {@code COMBO} findings — for example
 * "networking + dynamic class loading = remote code loader" — each carrying the rule ids that
 * triggered it. A {@code CRITICAL} combo also floors the overall verdict.
 */
@Component
@Order(1000)
public class CorrelationAnalyzer implements Analyzer {

    @Override
    public String name() {
        return "correlation";
    }

    @Override
    public void analyze(AnalysisContext ctx) {
        // Snapshot the rule ids present per category before we add anything ourselves.
        Set<String> rules = new LinkedHashSet<>();
        EnumSet<Category> categories = EnumSet.noneOf(Category.class);
        for (Finding f : ctx.findings()) {
            rules.add(f.ruleId());
            categories.add(f.category());
        }

        boolean classLoading = categories.contains(Category.CLASS_LOADING);
        boolean network = categories.contains(Category.NETWORK);
        boolean process = categories.contains(Category.PROCESS) || rules.contains("IOC_SHELL_COMMAND");
        boolean reflection = categories.contains(Category.REFLECTION);
        boolean crypto = rules.contains("BYTECODE_CRYPTO");
        boolean scripting = categories.contains(Category.SCRIPTING);
        boolean deserialization = categories.contains(Category.DESERIALIZATION);
        boolean nativeCode = categories.contains(Category.NATIVE);
        boolean encodedPayload = rules.contains("DECODE_EMBEDDED_CLASS")
                || rules.contains("DECODE_EMBEDDED_ARCHIVE")
                || rules.contains("DECODE_EMBEDDED_NATIVE")
                || rules.contains("DECODE_HIDDEN_IOC")
                || rules.contains("IOC_BASE64_BLOBS");
        boolean credentialTheft = rules.contains("IOC_CREDENTIAL_TARGET");
        boolean exfilChannel = network
                || rules.contains("IOC_DISCORD_WEBHOOK")
                || rules.contains("IOC_TELEGRAM_API")
                || rules.contains("IOC_HARDCODED_IP");

        List<Combo> combos = new ArrayList<>();

        if (network && classLoading) {
            combos.add(new Combo("COMBO_REMOTE_CODE_LOADER", Severity.CRITICAL, 60,
                    "Remote code loader (network + dynamic class loading)",
                    "The plugin both reaches the network and defines/loads classes at runtime. Together these let it "
                            + "download and execute code that is not present in the JAR you are scanning — the defining "
                            + "trait of a remote-payload backdoor.",
                    "Do not install unless this exact mechanism is documented and the source is trusted.",
                    related(ctx, Category.NETWORK, Category.CLASS_LOADING)));
        }
        if (classLoading && (crypto || encodedPayload)) {
            combos.add(new Combo("COMBO_ENCRYPTED_LOADER", Severity.CRITICAL, 55,
                    "Encrypted/encoded payload loader",
                    "The plugin loads classes at runtime while also decrypting or decoding data. This is how a hidden "
                            + "payload is unpacked from an encrypted/encoded blob and executed, defeating a plain "
                            + "static read of the code.",
                    "Treat as high risk; the real behaviour is hidden until runtime.",
                    related(ctx, Category.CLASS_LOADING, Category.CRYPTO)));
        }
        if (reflection && process) {
            combos.add(new Combo("COMBO_REFLECTIVE_PROCESS", Severity.HIGH, 45,
                    "Reflection-hidden process execution",
                    "Reflection is used alongside process-execution signals. Building Runtime/ProcessBuilder calls "
                            + "through reflection is a deliberate way to hide command execution from a direct-call scan.",
                    "Inspect what command is ultimately run.",
                    related(ctx, Category.REFLECTION, Category.PROCESS)));
        }
        if (deserialization && exfilChannel) {
            combos.add(new Combo("COMBO_UNTRUSTED_DESERIALIZATION", Severity.HIGH, 40,
                    "Deserialization of network data",
                    "Java deserialization is combined with networking. Deserializing data received over the network is "
                            + "a classic remote-code-execution vector through gadget chains.",
                    "Confirm deserialized data is never sourced from the network or untrusted input.",
                    related(ctx, Category.DESERIALIZATION, Category.NETWORK)));
        }
        if (nativeCode && process) {
            combos.add(new Combo("COMBO_DROPPER", Severity.CRITICAL, 55,
                    "Dropper (bundled native binary + process execution)",
                    "The plugin ships native/executable content and is able to launch processes. That combination is a "
                            + "dropper: write a binary to disk and run it outside the JVM's protections.",
                    "Treat as malicious unless there is a clearly documented, trusted reason.",
                    related(ctx, Category.NATIVE, Category.PROCESS)));
        }
        if (scripting && exfilChannel) {
            combos.add(new Combo("COMBO_REMOTE_SCRIPTING", Severity.CRITICAL, 55,
                    "Scripting engine with a network channel",
                    "A scripting engine (general code execution) is combined with networking. If script source can come "
                            + "from the network, this is arbitrary remote code execution.",
                    "Verify all script sources are static, bundled and trusted.",
                    related(ctx, Category.SCRIPTING, Category.NETWORK)));
        }
        if (credentialTheft && exfilChannel) {
            combos.add(new Combo("COMBO_CREDENTIAL_STEALER", Severity.CRITICAL, 60,
                    "Credential stealer with exfiltration",
                    "The plugin references credential/account files (launcher accounts, SSH keys) and also has a network "
                            + "channel to send data out. This is the signature of an account/session stealer.",
                    "Do not install. This pattern exists almost exclusively to steal credentials.",
                    related(ctx, Category.FILESYSTEM, Category.NETWORK)));
        }

        for (Combo c : combos) {
            ctx.add(Finding.builder(c.ruleId(), Category.COMBO, c.severity())
                    .title(c.title())
                    .description(c.description())
                    .recommendation(c.recommendation())
                    .evidence("correlated: " + String.join(", ", c.related()))
                    .relatedRuleIds(c.related())
                    .scoreImpact(c.scoreImpact())
                    .build());
        }
    }

    /** Collects the rule ids already present that belong to any of the given categories. */
    private static List<String> related(AnalysisContext ctx, Category... cats) {
        EnumSet<Category> set = EnumSet.noneOf(Category.class);
        for (Category c : cats) {
            set.add(c);
        }
        Set<String> ids = new LinkedHashSet<>();
        for (Finding f : ctx.findings()) {
            if (set.contains(f.category())) {
                ids.add(f.ruleId());
            }
        }
        // Also fold in the well-known string-IOC rules that imply these categories.
        for (Finding f : ctx.findings()) {
            String id = f.ruleId();
            if (set.contains(Category.NETWORK)
                    && (id.equals("IOC_DISCORD_WEBHOOK") || id.equals("IOC_TELEGRAM_API") || id.equals("IOC_HARDCODED_IP"))) {
                ids.add(id);
            }
            if (set.contains(Category.PROCESS) && id.equals("IOC_SHELL_COMMAND")) {
                ids.add(id);
            }
            if (set.contains(Category.FILESYSTEM) && id.equals("IOC_CREDENTIAL_TARGET")) {
                ids.add(id);
            }
        }
        return new ArrayList<>(ids);
    }

    private record Combo(String ruleId, Severity severity, int scoreImpact, String title,
                         String description, String recommendation, List<String> related) {
    }
}
