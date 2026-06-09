package dev.pluginguard.engine.analyzers;

import dev.pluginguard.engine.AnalysisContext;
import dev.pluginguard.engine.Analyzer;
import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.bytecode.Invocation;
import dev.pluginguard.engine.model.Category;
import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.Severity;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The core analyzer. Walks every method call site collected during the single ASM pass and matches
 * it against a table of security-relevant JDK APIs: process execution, dynamic / remote class
 * loading, native loading, reflection, networking, filesystem mutation, crypto and JVM control.
 *
 * <p>A matched call is reported with its class + method location and a plain-language explanation —
 * the point is to show an admin <em>where</em> and <em>what</em>, not to claim certainty of malice
 * (many of these calls are legitimate). Findings are de-duplicated per call-site and capped per rule.
 */
@Component
@Order(30)
public class BytecodeAnalyzer implements Analyzer {

    private static final int MAX_FINDINGS_PER_RULE = 25;

    private final List<Rule> rules = buildRules();

    @Override
    public String name() {
        return "bytecode";
    }

    @Override
    public void analyze(AnalysisContext ctx) {
        Set<String> seen = new HashSet<>();
        Map<String, Integer> perRuleCount = new LinkedHashMap<>();
        Map<String, Integer> perRuleSuppressed = new LinkedHashMap<>();

        for (ClassScan scan : ctx.classScans()) {
            for (Invocation inv : scan.invocations()) {
                Rule rule = match(inv);
                if (rule == null) {
                    continue;
                }
                String location = inv.callerClass().replace('/', '.') + "#" + inv.callerMethod();
                String key = rule.ruleId() + "|" + location;
                if (!seen.add(key)) {
                    continue;
                }
                int count = perRuleCount.merge(rule.ruleId(), 1, Integer::sum);
                if (count > MAX_FINDINGS_PER_RULE) {
                    perRuleSuppressed.merge(rule.ruleId(), 1, Integer::sum);
                    continue;
                }
                ctx.add(Finding.builder(rule.ruleId(), rule.category(), rule.severity())
                        .title(rule.title())
                        .description(rule.description())
                        .recommendation(rule.recommendation())
                        .location(location)
                        .evidence(inv.ownerDotted() + "." + inv.name() + "()")
                        .scoreImpact(rule.scoreImpact())
                        .build());
            }
        }

        perRuleSuppressed.forEach((ruleId, suppressed) ->
                ctx.addNote("Rule " + ruleId + ": " + suppressed
                        + " additional call site(s) beyond the first " + MAX_FINDINGS_PER_RULE + " were not listed."));
    }

    private Rule match(Invocation inv) {
        for (Rule rule : rules) {
            if (rule.matches(inv)) {
                return rule;
            }
        }
        return null;
    }

    /**
     * A matcher over an {@link Invocation}.
     *
     * @param owner       owner internal name; if {@code prefix} is true this is a package prefix
     * @param prefix      whether {@code owner} is matched by prefix instead of exact
     * @param methodNames method names to match; empty means "any method"
     */
    private record Rule(String ruleId, String owner, boolean prefix, Set<String> methodNames,
                        Category category, Severity severity, String title, String description,
                        String recommendation, int scoreImpact) {

        boolean matches(Invocation inv) {
            boolean ownerOk = prefix ? inv.owner().startsWith(owner) : inv.owner().equals(owner);
            if (!ownerOk) {
                return false;
            }
            return methodNames.isEmpty() || methodNames.contains(inv.name());
        }
    }

    private static List<Rule> buildRules() {
        List<Rule> r = new ArrayList<>();

        // --- Process execution -------------------------------------------------------------
        r.add(new Rule("BYTECODE_RUNTIME_EXEC", "java/lang/Runtime", false, Set.of("exec"),
                Category.PROCESS, Severity.HIGH,
                "Runs operating-system commands",
                "Calls Runtime.exec(), which launches external OS processes. This is one of the strongest "
                        + "indicators of a backdoor or dropper when not clearly justified.",
                "Only safe if the plugin documents exactly which command it runs and why.", 40));
        r.add(new Rule("BYTECODE_PROCESS_BUILDER", "java/lang/ProcessBuilder", false, Set.of("<init>", "start"),
                Category.PROCESS, Severity.HIGH,
                "Launches external processes",
                "Uses ProcessBuilder to start external OS processes — the same capability as Runtime.exec().",
                "Verify which executable is launched and whether it ships inside the JAR.", 40));

        // --- Dynamic / remote class loading ------------------------------------------------
        r.add(new Rule("BYTECODE_DEFINE_CLASS", "java/lang/ClassLoader", false, Set.of("defineClass"),
                Category.CLASS_LOADING, Severity.HIGH,
                "Defines classes at runtime",
                "Calls ClassLoader.defineClass(), which turns raw bytes into runnable classes. Combined with "
                        + "network or decryption code, this is how plugins load hidden remote payloads.",
                "High risk if the bytes come from the network or a decrypted/obfuscated blob.", 35));
        r.add(new Rule("BYTECODE_URL_CLASSLOADER", "java/net/URLClassLoader", false, Set.of(),
                Category.CLASS_LOADING, Severity.HIGH,
                "Loads classes from a URL/file",
                "Creates a URLClassLoader, which can load and run code from an arbitrary URL or file at runtime.",
                "Check whether the source URL is remote — remote class loading is a major red flag.", 35));
        r.add(new Rule("BYTECODE_NATIVE_LOAD", "java/lang/System", false, Set.of("load", "loadLibrary"),
                Category.NATIVE, Severity.HIGH,
                "Loads a native library",
                "Calls System.load()/loadLibrary() to load native code that runs outside the JVM's protections.",
                "Native loading is uncommon for plugins and warrants close review.", 30));

        // --- Reflection --------------------------------------------------------------------
        r.add(new Rule("BYTECODE_CLASS_FORNAME", "java/lang/Class", false, Set.of("forName"),
                Category.REFLECTION, Severity.MEDIUM,
                "Resolves classes by name (reflection)",
                "Uses Class.forName() to look up classes by name at runtime. Common for NMS/version-specific code, "
                        + "but also used to hide which APIs are called.",
                "Usually benign in Minecraft plugins; review if combined with networking or obfuscation.", 6));
        r.add(new Rule("BYTECODE_REFLECT_INVOKE", "java/lang/reflect/Method", false, Set.of("invoke"),
                Category.REFLECTION, Severity.MEDIUM,
                "Invokes methods via reflection",
                "Uses reflection (Method.invoke) to call methods indirectly, which can obscure behaviour.",
                "Common in plugins; review only if the plugin is also obfuscated.", 5));
        r.add(new Rule("BYTECODE_METHODHANDLES", "java/lang/invoke/MethodHandles$Lookup", false, Set.of(),
                Category.REFLECTION, Severity.MEDIUM,
                "Uses MethodHandles for dynamic access",
                "Uses MethodHandles.Lookup, a low-level reflection mechanism that can bypass access checks.",
                "Review when paired with class definition or networking.", 6));
        r.add(new Rule("BYTECODE_UNSAFE", "sun/misc/Unsafe", false, Set.of(),
                Category.REFLECTION, Severity.HIGH,
                "Uses sun.misc.Unsafe",
                "Accesses sun.misc.Unsafe, which allows direct memory manipulation and bypassing JVM safety.",
                "Rarely needed by plugins; treat with suspicion.", 15));

        // --- Networking --------------------------------------------------------------------
        r.add(new Rule("BYTECODE_SOCKET", "java/net/Socket", false, Set.of("<init>"),
                Category.NETWORK, Severity.MEDIUM,
                "Opens raw network sockets",
                "Creates raw TCP sockets, which can be used for custom command-and-control channels.",
                "Check the destination host/port; raw sockets are unusual for ordinary plugins.", 12));
        r.add(new Rule("BYTECODE_SERVER_SOCKET", "java/net/ServerSocket", false, Set.of("<init>"),
                Category.NETWORK, Severity.MEDIUM,
                "Listens for inbound connections",
                "Opens a ServerSocket to accept inbound network connections.",
                "Verify why the plugin needs to listen for connections.", 12));
        r.add(new Rule("BYTECODE_HTTP_URLCONN", "java/net/HttpURLConnection", false, Set.of(),
                Category.NETWORK, Severity.LOW,
                "Makes HTTP requests",
                "Performs HTTP requests via HttpURLConnection. Often legitimate (updates, metrics, webhooks).",
                "Check the destination — see the Network summary for the actual hosts.", 8));
        r.add(new Rule("BYTECODE_HTTP_CLIENT", "java/net/http/HttpClient", false, Set.of(),
                Category.NETWORK, Severity.LOW,
                "Makes HTTP requests",
                "Performs HTTP requests via the java.net.http HttpClient.",
                "Check the destination — see the Network summary for the actual hosts.", 8));
        r.add(new Rule("BYTECODE_URL_OPEN", "java/net/URL", false, Set.of("openConnection", "openStream"),
                Category.NETWORK, Severity.LOW,
                "Opens network connections from URLs",
                "Opens a connection/stream from a URL, e.g. to download content.",
                "Confirm the URLs are expected — see the Network summary.", 6));

        // --- Filesystem --------------------------------------------------------------------
        r.add(new Rule("BYTECODE_FILES_DELETE", "java/nio/file/Files", false, Set.of("delete", "deleteIfExists"),
                Category.FILESYSTEM, Severity.MEDIUM,
                "Deletes files",
                "Calls Files.delete(), which removes files from disk.",
                "Confirm the plugin only deletes its own data, not arbitrary paths.", 8));
        r.add(new Rule("BYTECODE_FILES_WRITE", "java/nio/file/Files", false, Set.of("write", "newOutputStream", "newBufferedWriter"),
                Category.FILESYSTEM, Severity.LOW,
                "Writes files",
                "Writes to the filesystem. Normal for config/log handling, but worth noting.",
                "Usually benign; see the Filesystem summary for paths.", 3));

        // --- Crypto ------------------------------------------------------------------------
        r.add(new Rule("BYTECODE_CRYPTO", "javax/crypto/Cipher", false, Set.of("getInstance", "doFinal"),
                Category.CRYPTO, Severity.LOW,
                "Uses encryption/decryption",
                "Uses javax.crypto. Legitimate for secure communication, but also used to hide payloads "
                        + "(decrypting bundled blobs before loading them).",
                "Suspicious only when combined with class loading or networking.", 4));

        // --- JVM control -------------------------------------------------------------------
        r.add(new Rule("BYTECODE_SYSTEM_EXIT", "java/lang/System", false, Set.of("exit"),
                Category.SYSTEM, Severity.MEDIUM,
                "Can shut down the server JVM",
                "Calls System.exit(), which would terminate the entire Minecraft server process.",
                "A plugin should never kill the JVM; investigate this call.", 8));
        r.add(new Rule("BYTECODE_RUNTIME_HALT", "java/lang/Runtime", false, Set.of("halt"),
                Category.SYSTEM, Severity.HIGH,
                "Can force-kill the server JVM",
                "Calls Runtime.halt(), an abrupt JVM shutdown that skips all cleanup.",
                "Extremely unusual for a plugin; treat as hostile unless clearly justified.", 12));

        return r;
    }
}
