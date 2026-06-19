package dev.pluginguard.engine.analyzers;

import dev.pluginguard.engine.AnalysisContext;
import dev.pluginguard.engine.Analyzer;
import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.bytecode.IndyBootstraps;
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
 * it against a table of security-relevant JDK / library APIs: process execution, dynamic / remote
 * class loading, native loading, reflection and access-control bypass, scripting engines,
 * JNDI/RMI, deserialization, networking, filesystem mutation, crypto, AWT capture and JVM control.
 *
 * <p>Beyond the static table it performs three extra passes: it resolves reflection targets from
 * adjacent string constants (e.g. {@code Class.forName("java.lang.Runtime")}), it flags
 * non-standard {@code invokedynamic} bootstraps (an obfuscation signal), and it applies a
 * per-class time-bomb heuristic (a scheduler/sleep combined with date checks).
 *
 * <p>A matched call is reported with its class + method location and a plain-language explanation —
 * the point is to show an admin <em>where</em> and <em>what</em>, not to claim certainty of malice
 * (many of these calls are legitimate). Findings are de-duplicated per call-site and capped per rule.
 */
@Component
@Order(30)
public class BytecodeAnalyzer implements Analyzer {

    private static final int MAX_FINDINGS_PER_RULE = 25;

    /** Dotted class names that are dangerous to resolve reflectively via {@code Class.forName}. */
    private static final Set<String> DANGEROUS_FORNAME_CLASSES = Set.of(
            "java.lang.Runtime", "java.lang.ProcessBuilder",
            "javax.script.ScriptEngineManager", "javax.naming.InitialContext",
            "sun.misc.Unsafe", "jdk.internal.misc.Unsafe",
            "java.net.URLClassLoader", "groovy.lang.GroovyShell",
            "groovy.lang.GroovyClassLoader", "bsh.Interpreter",
            "org.mozilla.javascript.Context");

    /** Method-name operands that are dangerous to look up reflectively via {@code getMethod}. */
    private static final Set<String> DANGEROUS_METHOD_OPERANDS = Set.of(
            "exec", "defineClass", "load", "loadLibrary", "setAccessible",
            "setSecurityManager", "halt", "addShutdownHook");

    private static final Set<String> REFLECT_LOOKUP_METHODS = Set.of(
            "getMethod", "getDeclaredMethod");

    /** {@code MethodHandles.Lookup} finders that take a method name as their second argument. */
    private static final Set<String> METHODHANDLE_FIND_METHODS = Set.of(
            "findVirtual", "findStatic", "findSpecial");

    private static final Set<String> SCHEDULER_OWNERS = Set.of(
            "java/util/Timer", "java/util/concurrent/ScheduledThreadPoolExecutor",
            "java/util/concurrent/ScheduledExecutorService");

    private final List<Rule> rules = buildRules();

    @Override
    public String name() {
        return "bytecode";
    }

    @Override
    public void analyze(AnalysisContext ctx) {
        Emitter emitter = new Emitter();

        for (ClassScan scan : ctx.classScans()) {
            String location = scan.displayName();
            String nestedPath = scan.nestedPath();

            for (Invocation inv : scan.invocations()) {
                Rule rule = match(inv);
                if (rule != null) {
                    String where = location + "#" + inv.callerMethod();
                    emitter.emit(ctx, Finding.builder(rule.ruleId(), rule.category(), rule.severity())
                            .title(rule.title())
                            .description(rule.description())
                            .recommendation(rule.recommendation())
                            .location(where)
                            .evidence(inv.ownerDotted() + "." + inv.name() + "()")
                            .nestedPath(nestedPath)
                            .scoreImpact(rule.scoreImpact())
                            .build());
                }
                resolveReflection(ctx, emitter, inv, location, nestedPath);
                if (IndyBootstraps.isCustom(inv)) {
                    emitter.emit(ctx, Finding.builder("BYTECODE_INDY_CUSTOM_BOOTSTRAP", Category.OBFUSCATION, Severity.MEDIUM)
                            .title("Non-standard invokedynamic bootstrap")
                            .description("An invokedynamic instruction is wired to a custom bootstrap (" + inv.ownerDotted()
                                    + "), not the standard lambda/string-concat factories. Obfuscators use this to "
                                    + "resolve the real call target only at runtime, hiding it from static analysis.")
                            .recommendation("Treat as an obfuscation signal; review carefully if other risky calls are present.")
                            .location(location + "#" + inv.callerMethod())
                            .evidence(inv.ownerDotted() + "." + inv.name() + "()")
                            .nestedPath(nestedPath)
                            .scoreImpact(10)
                            .build());
                }
            }

            detectTimeBomb(ctx, emitter, scan, location, nestedPath);
        }

        emitter.flushNotes(ctx);
    }

    /** Resolves {@code Class.forName("...")} / {@code getMethod("...")} string operands to targets. */
    private void resolveReflection(AnalysisContext ctx, Emitter emitter, Invocation inv,
                                   String location, String nestedPath) {
        String operand = inv.stringOperand();
        if (operand == null || operand.isBlank()) {
            return;
        }
        if (inv.owner().equals("java/lang/Class") && inv.name().equals("forName")
                && DANGEROUS_FORNAME_CLASSES.contains(operand.trim())) {
            emitter.emit(ctx, Finding.builder("BYTECODE_REFLECTIVE_DANGEROUS_CLASS", Category.REFLECTION, Severity.HIGH)
                    .title("Resolves a dangerous class by name (reflection)")
                    .description("Reflectively resolves '" + operand.trim() + "' via Class.forName(). Resolving "
                            + "process, scripting, JNDI or class-loading APIs by name is a common way to hide "
                            + "dangerous behaviour from static scanners.")
                    .recommendation("Confirm why this class is loaded reflectively rather than referenced directly.")
                    .location(location + "#" + inv.callerMethod())
                    .evidence("Class.forName(\"" + operand.trim() + "\")")
                    .nestedPath(nestedPath)
                    .scoreImpact(28)
                    .build());
        }
        boolean reflectLookup = REFLECT_LOOKUP_METHODS.contains(inv.name());
        boolean methodHandleFind = inv.owner().equals("java/lang/invoke/MethodHandles$Lookup")
                && METHODHANDLE_FIND_METHODS.contains(inv.name());
        if ((reflectLookup || methodHandleFind) && DANGEROUS_METHOD_OPERANDS.contains(operand.trim())) {
            String mechanism = methodHandleFind ? "a MethodHandles.Lookup finder" : "reflection";
            emitter.emit(ctx, Finding.builder("BYTECODE_REFLECTIVE_DANGEROUS_METHOD", Category.REFLECTION, Severity.HIGH)
                    .title("Looks up a dangerous method by name (reflection)")
                    .description("Looks up the method '" + operand.trim() + "' by name via " + inv.name()
                            + " (" + mechanism + "). Combined with an indirect invoke this can call "
                            + "process-execution or class-loading APIs while keeping them invisible to a direct-call scan.")
                    .recommendation("Strong red flag when paired with reflective class resolution or networking.")
                    .location(location + "#" + inv.callerMethod())
                    .evidence(inv.name() + "(\"" + operand.trim() + "\")")
                    .nestedPath(nestedPath)
                    .scoreImpact(22)
                    .build());
        }
    }

    /** Per-class heuristic: a scheduler or {@code Thread.sleep} together with date checks = delayed activation. */
    private void detectTimeBomb(AnalysisContext ctx, Emitter emitter, ClassScan scan,
                                String location, String nestedPath) {
        boolean scheduler = false;
        boolean dateCheck = false;
        for (Invocation inv : scan.invocations()) {
            String owner = inv.owner();
            if (SCHEDULER_OWNERS.contains(owner)
                    || (owner.equals("java/lang/Thread") && inv.name().equals("sleep"))) {
                scheduler = true;
            }
            if (owner.startsWith("java/time/")
                    || owner.equals("java/util/Calendar") || owner.equals("java/util/Date")
                    || (owner.equals("java/lang/System") && inv.name().equals("currentTimeMillis"))) {
                dateCheck = true;
            }
        }
        if (scheduler && dateCheck) {
            emitter.emit(ctx, Finding.builder("BYTECODE_TIME_BOMB", Category.SYSTEM, Severity.MEDIUM)
                    .title("Possible delayed activation (time-bomb)")
                    .description("This class schedules work or sleeps while also reading the current date/time. That "
                            + "combination is how 'time-bomb' payloads stay dormant until a target date, defeating a "
                            + "quick test run.")
                    .recommendation("Inspect what happens after the delay or on the checked date.")
                    .location(location)
                    .evidence("scheduler + date check in one class")
                    .nestedPath(nestedPath)
                    .scoreImpact(12)
                    .build());
        }
    }

    private Rule match(Invocation inv) {
        for (Rule rule : rules) {
            if (rule.matches(inv)) {
                return rule;
            }
        }
        return null;
    }

    /** De-duplicates by rule+location+evidence and caps the number of findings per rule. */
    private static final class Emitter {
        private final Set<String> seen = new HashSet<>();
        private final Map<String, Integer> count = new LinkedHashMap<>();
        private final Map<String, Integer> suppressed = new LinkedHashMap<>();

        void emit(AnalysisContext ctx, Finding f) {
            String key = f.ruleId() + "|" + nullSafe(f.location()) + "|" + nullSafe(f.evidence());
            if (!seen.add(key)) {
                return;
            }
            int c = count.merge(f.ruleId(), 1, Integer::sum);
            if (c > MAX_FINDINGS_PER_RULE) {
                suppressed.merge(f.ruleId(), 1, Integer::sum);
                return;
            }
            ctx.add(f);
        }

        void flushNotes(AnalysisContext ctx) {
            suppressed.forEach((ruleId, n) ->
                    ctx.addNote("Rule " + ruleId + ": " + n + " additional call site(s) beyond the first "
                            + MAX_FINDINGS_PER_RULE + " were not listed."));
        }

        private static String nullSafe(String s) {
            return s == null ? "" : s;
        }
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

    private static Rule rule(String id, String owner, Set<String> methods, Category cat, Severity sev,
                             String title, String desc, String rec, int impact) {
        return new Rule(id, owner, false, methods, cat, sev, title, desc, rec, impact);
    }

    private static Rule prefixRule(String id, String ownerPrefix, Category cat, Severity sev,
                                   String title, String desc, String rec, int impact) {
        return new Rule(id, ownerPrefix, true, Set.of(), cat, sev, title, desc, rec, impact);
    }

    /** Matches any owner whose internal name starts with {@code ownerPrefix} and calls one of {@code methods}. */
    private static Rule prefixMethodRule(String id, String ownerPrefix, Set<String> methods, Category cat,
                                         Severity sev, String title, String desc, String rec, int impact) {
        return new Rule(id, ownerPrefix, true, methods, cat, sev, title, desc, rec, impact);
    }

    /**
     * Matches a call to {@code methods} on <em>any</em> owner (empty prefix matches everything). Used
     * for signals where the owner is remapped/obfuscated but the method name is stable (e.g. the
     * Minecraft client session accessor {@code getAccessToken}).
     */
    private static Rule anyOwnerMethodRule(String id, Set<String> methods, Category cat, Severity sev,
                                           String title, String desc, String rec, int impact) {
        return new Rule(id, "", true, methods, cat, sev, title, desc, rec, impact);
    }

    private static List<Rule> buildRules() {
        List<Rule> r = new ArrayList<>();

        // --- Process execution & environment ----------------------------------------------
        r.add(rule("BYTECODE_RUNTIME_EXEC", "java/lang/Runtime", Set.of("exec"),
                Category.PROCESS, Severity.HIGH,
                "Runs operating-system commands",
                "Calls Runtime.exec(), which launches external OS processes. This is one of the strongest "
                        + "indicators of a backdoor or dropper when not clearly justified.",
                "Only safe if the plugin documents exactly which command it runs and why.", 40));
        r.add(rule("BYTECODE_PROCESS_BUILDER", "java/lang/ProcessBuilder", Set.of("<init>", "start"),
                Category.PROCESS, Severity.HIGH,
                "Launches external processes",
                "Uses ProcessBuilder to start external OS processes — the same capability as Runtime.exec().",
                "Verify which executable is launched and whether it ships inside the JAR.", 40));
        r.add(rule("BYTECODE_PROCESS_HANDLE", "java/lang/ProcessHandle", Set.of(),
                Category.PROCESS, Severity.MEDIUM,
                "Enumerates or controls OS processes",
                "Uses ProcessHandle to inspect, enumerate or terminate operating-system processes outside the JVM.",
                "Unusual for a plugin; confirm why it needs visibility into other processes.", 15));
        r.add(rule("BYTECODE_SHUTDOWN_HOOK", "java/lang/Runtime", Set.of("addShutdownHook"),
                Category.SYSTEM, Severity.LOW,
                "Registers a JVM shutdown hook",
                "Registers a shutdown hook that runs code as the server stops — occasionally used to persist or "
                        + "re-trigger behaviour.",
                "Usually benign for cleanup; review if combined with process or network calls.", 4));
        r.add(rule("BYTECODE_ENV_READ", "java/lang/System", Set.of("getenv"),
                Category.SYSTEM, Severity.INFO,
                "Reads environment variables",
                "Reads process environment variables (System.getenv), which can include secrets/tokens.",
                "Normal for configuration; note if the values are then sent over the network.", 2));

        // --- Dynamic / remote class loading ------------------------------------------------
        r.add(rule("BYTECODE_DEFINE_CLASS", "java/lang/ClassLoader", Set.of("defineClass"),
                Category.CLASS_LOADING, Severity.HIGH,
                "Defines classes at runtime",
                "Calls ClassLoader.defineClass(), which turns raw bytes into runnable classes. Combined with "
                        + "network or decryption code, this is how plugins load hidden remote payloads.",
                "High risk if the bytes come from the network or a decrypted/obfuscated blob.", 35));
        r.add(rule("BYTECODE_LOOKUP_DEFINE_CLASS", "java/lang/invoke/MethodHandles$Lookup", Set.of("defineClass", "defineHiddenClass"),
                Category.CLASS_LOADING, Severity.HIGH,
                "Defines classes via MethodHandles.Lookup",
                "Uses MethodHandles.Lookup.defineClass/defineHiddenClass to materialise new classes at runtime, "
                        + "including hidden classes that are hard to inspect.",
                "Strong red flag when the class bytes are decoded or downloaded.", 30));
        r.add(rule("BYTECODE_URL_CLASSLOADER", "java/net/URLClassLoader", Set.of(),
                Category.CLASS_LOADING, Severity.HIGH,
                "Loads classes from a URL/file",
                "Creates a URLClassLoader, which can load and run code from an arbitrary URL or file at runtime.",
                "Check whether the source URL is remote — remote class loading is a major red flag.", 35));
        r.add(prefixRule("BYTECODE_INSTRUMENTATION", "java/lang/instrument/", Category.CLASS_LOADING, Severity.HIGH,
                "Uses JVM instrumentation",
                "Uses java.lang.instrument to transform or redefine already-loaded classes — agent-level power "
                        + "that can rewrite the server or other plugins.",
                "Not normal for a plugin; investigate why instrumentation is needed.", 25));
        r.add(rule("BYTECODE_NATIVE_LOAD", "java/lang/System", Set.of("load", "loadLibrary"),
                Category.NATIVE, Severity.HIGH,
                "Loads a native library",
                "Calls System.load()/loadLibrary() to load native code that runs outside the JVM's protections.",
                "Native loading is uncommon for plugins and warrants close review.", 30));
        r.add(prefixRule("BYTECODE_FOREIGN_FUNCTION", "java/lang/foreign/", Category.NATIVE, Severity.HIGH,
                "Calls native code via the Foreign Function API",
                "Uses the java.lang.foreign API (Project Panama) to invoke native library functions directly, "
                        + "without System.loadLibrary. This runs native code outside the JVM's protections and is a "
                        + "newer way to reach native behaviour while sidestepping the usual native-loading signal.",
                "Very unusual for a plugin; confirm why it needs to call native functions directly.", 28));

        // --- Reflection & access-control bypass --------------------------------------------
        r.add(rule("BYTECODE_CLASS_FORNAME", "java/lang/Class", Set.of("forName"),
                Category.REFLECTION, Severity.MEDIUM,
                "Resolves classes by name (reflection)",
                "Uses Class.forName() to look up classes by name at runtime. Common for NMS/version-specific code, "
                        + "but also used to hide which APIs are called.",
                "Usually benign in Minecraft plugins; review if combined with networking or obfuscation.", 6));
        r.add(rule("BYTECODE_REFLECT_INVOKE", "java/lang/reflect/Method", Set.of("invoke"),
                Category.REFLECTION, Severity.MEDIUM,
                "Invokes methods via reflection",
                "Uses reflection (Method.invoke) to call methods indirectly, which can obscure behaviour.",
                "Common in plugins; review only if the plugin is also obfuscated.", 5));
        r.add(rule("BYTECODE_SET_ACCESSIBLE", "java/lang/reflect/AccessibleObject", Set.of("setAccessible"),
                Category.REFLECTION, Severity.MEDIUM,
                "Disables Java access checks",
                "Calls setAccessible(true) to bypass private/protected access checks via reflection, reaching "
                        + "internals it is not meant to touch.",
                "Common for deep integrations, but a building block for tampering; review in context.", 8));
        r.add(rule("BYTECODE_METHODHANDLES", "java/lang/invoke/MethodHandles$Lookup", Set.of(),
                Category.REFLECTION, Severity.MEDIUM,
                "Uses MethodHandles for dynamic access",
                "Uses MethodHandles.Lookup, a low-level reflection mechanism that can bypass access checks.",
                "Review when paired with class definition or networking.", 6));
        r.add(rule("BYTECODE_UNSAFE", "sun/misc/Unsafe", Set.of(),
                Category.REFLECTION, Severity.HIGH,
                "Uses sun.misc.Unsafe",
                "Accesses sun.misc.Unsafe, which allows direct memory manipulation and bypassing JVM safety.",
                "Rarely needed by plugins; treat with suspicion.", 15));
        r.add(prefixRule("BYTECODE_JDK_INTERNAL", "jdk/internal/", Category.REFLECTION, Severity.HIGH,
                "Accesses JDK internals (jdk.internal.*)",
                "References jdk.internal.* APIs, which are encapsulated by the module system and provide low-level "
                        + "access normally forbidden to applications.",
                "Strongly unusual for a plugin; investigate why module boundaries are bypassed.", 18));

        // --- Security-manager / privilege control ------------------------------------------
        r.add(rule("BYTECODE_SET_SECURITY_MANAGER", "java/lang/System", Set.of("setSecurityManager"),
                Category.SYSTEM, Severity.HIGH,
                "Changes or removes the SecurityManager",
                "Calls System.setSecurityManager(), which can disable the JVM's policy enforcement entirely.",
                "Removing the SecurityManager strips a layer of defence; treat as hostile unless justified.", 22));
        r.add(rule("BYTECODE_DO_PRIVILEGED", "java/security/AccessController", Set.of("doPrivileged"),
                Category.SYSTEM, Severity.LOW,
                "Runs code in a privileged block",
                "Uses AccessController.doPrivileged to elevate the permissions of a code block.",
                "Common in older libraries; review when combined with reflection or class loading.", 4));

        // --- Scripting engines -------------------------------------------------------------
        r.add(rule("BYTECODE_SCRIPT_ENGINE", "javax/script/ScriptEngineManager", Set.of(),
                Category.SCRIPTING, Severity.HIGH,
                "Runs a scripting engine (JSR-223)",
                "Creates a ScriptEngineManager, which can evaluate arbitrary JavaScript/Groovy/etc. at runtime — a "
                        + "general code-execution capability.",
                "A scripting engine is effectively eval(); confirm what scripts it runs and from where.", 28));
        r.add(rule("BYTECODE_SCRIPT_EVAL", "javax/script/ScriptEngine", Set.of("eval"),
                Category.SCRIPTING, Severity.HIGH,
                "Evaluates scripts at runtime",
                "Calls ScriptEngine.eval(), executing script source as code. If the source is dynamic, this is "
                        + "arbitrary code execution.",
                "Verify the script source is static and trusted.", 28));
        r.add(prefixRule("BYTECODE_GROOVY", "groovy/lang/", Category.SCRIPTING, Severity.HIGH,
                "Executes Groovy code",
                "Uses Groovy (GroovyShell/GroovyClassLoader) to compile and run code at runtime — full code execution.",
                "Confirm the Groovy source is bundled and trusted, not fetched or decoded.", 26));
        r.add(rule("BYTECODE_BEANSHELL", "bsh/Interpreter", Set.of(),
                Category.SCRIPTING, Severity.HIGH,
                "Executes BeanShell scripts",
                "Uses the BeanShell interpreter to evaluate code at runtime — a general code-execution capability.",
                "Confirm what BeanShell scripts run and from where.", 24));
        r.add(prefixRule("BYTECODE_RHINO", "org/mozilla/javascript/", Category.SCRIPTING, Severity.MEDIUM,
                "Executes JavaScript (Rhino)",
                "Embeds the Rhino JavaScript engine to run scripts at runtime.",
                "Review what scripts run; dynamic script sources are code execution.", 16));
        r.add(prefixRule("BYTECODE_JYTHON", "org/python/util/", Category.SCRIPTING, Severity.MEDIUM,
                "Executes Python (Jython)",
                "Embeds Jython to run Python code inside the JVM.",
                "Review what scripts run and whether their source is trusted.", 16));

        // --- JNDI / RMI (Log4Shell class) --------------------------------------------------
        r.add(rule("BYTECODE_JNDI_LOOKUP", "javax/naming/InitialContext", Set.of("lookup", "doLookup"),
                Category.CLASS_LOADING, Severity.HIGH,
                "Performs a JNDI lookup",
                "Calls InitialContext.lookup(). A JNDI lookup against an attacker-controlled ldap:// or rmi:// URL "
                        + "can fetch and run remote code (the Log4Shell class of vulnerability).",
                "Verify the lookup name is static and local, never built from external input.", 26));
        r.add(prefixRule("BYTECODE_RMI", "java/rmi/", Category.NETWORK, Severity.MEDIUM,
                "Uses Java RMI",
                "Uses Java RMI, a remote-invocation mechanism that can be a channel for remote code or data.",
                "Confirm any RMI endpoints are expected and trusted.", 12));

        // --- Deserialization ---------------------------------------------------------------
        r.add(rule("BYTECODE_OBJECT_INPUT_STREAM", "java/io/ObjectInputStream", Set.of("readObject", "readUnshared", "<init>"),
                Category.DESERIALIZATION, Severity.MEDIUM,
                "Deserializes Java objects",
                "Reads serialized Java objects (ObjectInputStream.readObject). Deserializing untrusted data is a "
                        + "classic remote-code-execution vector via gadget chains.",
                "Safe only if the data is trusted/local; high risk if it comes from the network.", 14));
        r.add(prefixRule("BYTECODE_XSTREAM", "com/thoughtworks/xstream/", Category.DESERIALIZATION, Severity.MEDIUM,
                "Deserializes with XStream",
                "Uses XStream, which can instantiate arbitrary types during deserialization unless tightly "
                        + "whitelisted — a known RCE vector.",
                "Confirm XStream input is trusted and type permissions are restricted.", 14));

        // --- Networking --------------------------------------------------------------------
        r.add(rule("BYTECODE_SOCKET", "java/net/Socket", Set.of("<init>"),
                Category.NETWORK, Severity.MEDIUM,
                "Opens raw network sockets",
                "Creates raw TCP sockets, which can be used for custom command-and-control channels.",
                "Check the destination host/port; raw sockets are unusual for ordinary plugins.", 12));
        r.add(rule("BYTECODE_SERVER_SOCKET", "java/net/ServerSocket", Set.of("<init>"),
                Category.NETWORK, Severity.MEDIUM,
                "Listens for inbound connections",
                "Opens a ServerSocket to accept inbound network connections.",
                "Verify why the plugin needs to listen for connections.", 12));
        r.add(prefixMethodRule("BYTECODE_HTTP_SERVER", "com/sun/net/httpserver/",
                Set.of("create", "bind", "start"),
                Category.NETWORK, Severity.MEDIUM,
                "Runs an embedded HTTP server (listens for connections)",
                "Uses com.sun.net.httpserver.HttpServer/HttpsServer to bind a port and accept inbound HTTP "
                        + "requests inside the JVM — a network listener and remote-control surface. Legitimate for "
                        + "local bridges, metrics or debug endpoints, but it is also how a plugin/mod exposes game "
                        + "or host control over HTTP, especially if it binds beyond 127.0.0.1 or skips authentication.",
                "Check the bind address (127.0.0.1 vs 0.0.0.0), whether requests are authenticated, and what the "
                        + "exposed endpoints can do.", 14));
        r.add(rule("BYTECODE_DATAGRAM_SOCKET", "java/net/DatagramSocket", Set.of("<init>"),
                Category.NETWORK, Severity.MEDIUM,
                "Opens UDP sockets",
                "Creates a UDP DatagramSocket. UDP is harder to monitor and is sometimes used for covert channels.",
                "Confirm the plugin's stated features require UDP.", 10));
        r.add(rule("BYTECODE_MULTICAST_SOCKET", "java/net/MulticastSocket", Set.of("<init>"),
                Category.NETWORK, Severity.MEDIUM,
                "Uses multicast networking",
                "Opens a MulticastSocket for group networking on the local network.",
                "Uncommon for plugins; confirm it is expected (e.g. LAN discovery).", 8));
        r.add(rule("BYTECODE_HTTP_URLCONN", "java/net/HttpURLConnection", Set.of(),
                Category.NETWORK, Severity.LOW,
                "Makes HTTP requests",
                "Performs HTTP requests via HttpURLConnection. Often legitimate (updates, metrics, webhooks).",
                "Check the destination — see the Network summary for the actual hosts.", 8));
        r.add(rule("BYTECODE_HTTP_CLIENT", "java/net/http/HttpClient", Set.of(),
                Category.NETWORK, Severity.LOW,
                "Makes HTTP requests",
                "Performs HTTP requests via the java.net.http HttpClient.",
                "Check the destination — see the Network summary for the actual hosts.", 8));
        r.add(rule("BYTECODE_URL_OPEN", "java/net/URL", Set.of("openConnection", "openStream"),
                Category.NETWORK, Severity.LOW,
                "Opens network connections from URLs",
                "Opens a connection/stream from a URL, e.g. to download content.",
                "Confirm the URLs are expected — see the Network summary.", 6));

        // --- AWT capture / desktop ---------------------------------------------------------
        r.add(rule("BYTECODE_AWT_ROBOT", "java/awt/Robot", Set.of(),
                Category.SYSTEM, Severity.HIGH,
                "Captures screen/keyboard input (AWT Robot)",
                "Uses java.awt.Robot, which can take screenshots and synthesise/observe keyboard and mouse input — "
                        + "the building block of a keylogger or screen grabber.",
                "A server plugin has no legitimate need for Robot; treat as hostile.", 26));
        r.add(rule("BYTECODE_DESKTOP", "java/awt/Desktop", Set.of("browse", "open", "edit"),
                Category.SYSTEM, Severity.MEDIUM,
                "Opens files/URLs in the host desktop",
                "Uses java.awt.Desktop to open URLs, files or editors on the host machine's desktop session.",
                "Headless servers have no desktop; this is suspicious in a plugin.", 14));
        r.add(prefixRule("BYTECODE_CLIPBOARD", "java/awt/datatransfer/", Category.SYSTEM, Severity.MEDIUM,
                "Reads the system clipboard",
                "Accesses the AWT clipboard, which can read whatever the user has copied (passwords, tokens).",
                "Clipboard access is unusual for a server plugin; review it.", 12));

        // --- Crypto ------------------------------------------------------------------------
        r.add(rule("BYTECODE_CRYPTO", "javax/crypto/Cipher", Set.of("getInstance", "doFinal"),
                Category.CRYPTO, Severity.LOW,
                "Uses encryption/decryption",
                "Uses javax.crypto. Legitimate for secure communication, but also used to hide payloads "
                        + "(decrypting bundled blobs before loading them).",
                "Suspicious only when combined with class loading or networking.", 4));

        // --- Filesystem mutation -----------------------------------------------------------
        r.add(rule("BYTECODE_FILE_MAKE_EXECUTABLE", "java/io/File", Set.of("setExecutable"),
                Category.FILESYSTEM, Severity.HIGH,
                "Marks a file as executable",
                "Calls File.setExecutable() to give a file the execute permission. Writing a file and then making "
                        + "it executable is the core of a dropper: stage a binary on disk, then run it.",
                "Strong red flag when combined with file writes, bundled binaries or process execution.", 20));
        r.add(rule("BYTECODE_POSIX_PERMISSIONS", "java/nio/file/Files", Set.of("setPosixFilePermissions"),
                Category.FILESYSTEM, Severity.HIGH,
                "Changes POSIX file permissions",
                "Calls Files.setPosixFilePermissions(), which can add the execute bit to a file — the same "
                        + "dropper building block as File.setExecutable().",
                "Review which file is being chmod-ed and whether it is then executed.", 18));
        r.add(rule("BYTECODE_FILE_WRITE", "java/nio/file/Files",
                Set.of("write", "writeString", "newOutputStream", "newBufferedWriter", "copy", "move"),
                Category.FILESYSTEM, Severity.LOW,
                "Writes files to disk",
                "Writes to the filesystem via java.nio.file.Files. Normal for plugins that persist config/data, "
                        + "but it is also how a payload is staged on disk before it is loaded or executed.",
                "Usually benign; review if combined with networking, decoding or process execution.", 4));
        r.add(rule("BYTECODE_FILE_OUTPUT_STREAM", "java/io/FileOutputStream", Set.of("<init>"),
                Category.FILESYSTEM, Severity.LOW,
                "Writes files to disk",
                "Opens a FileOutputStream to write a file. Normal for saving config/data, but also the way a "
                        + "dropped payload is written to disk.",
                "Usually benign; review if combined with networking, decoding or process execution.", 4));
        r.add(rule("BYTECODE_FILE_DELETE", "java/nio/file/Files", Set.of("delete", "deleteIfExists"),
                Category.FILESYSTEM, Severity.INFO,
                "Deletes files",
                "Deletes files via java.nio.file.Files. Routine for cleanup, but also used for anti-forensics "
                        + "(removing traces after running).",
                "Informational; review only alongside other suspicious behaviour.", 2));

        // --- JVM control -------------------------------------------------------------------
        r.add(rule("BYTECODE_SYSTEM_EXIT", "java/lang/System", Set.of("exit"),
                Category.SYSTEM, Severity.MEDIUM,
                "Can shut down the server JVM",
                "Calls System.exit(), which would terminate the entire Minecraft server process.",
                "A plugin should never kill the JVM; investigate this call.", 8));
        r.add(rule("BYTECODE_RUNTIME_HALT", "java/lang/Runtime", Set.of("halt"),
                Category.SYSTEM, Severity.HIGH,
                "Can force-kill the server JVM",
                "Calls Runtime.halt(), an abrupt JVM shutdown that skips all cleanup.",
                "Extremely unusual for a plugin; treat as hostile unless clearly justified.", 12));

        // --- Minecraft platform-specific capabilities --------------------------------------
        // These are not JDK APIs, so a generic scanner misses them, yet they are the building
        // blocks of the most common Minecraft backdoor: silently granting the attacker operator
        // rights or running console commands. ASM reads the owner from the constant pool, so we
        // match the Bukkit/Spigot/Paper API by name without it being on the classpath.
        r.add(rule("BYTECODE_BUKKIT_CONSOLE_DISPATCH", "org/bukkit/Bukkit", Set.of("dispatchCommand"),
                Category.MINECRAFT, Severity.MEDIUM,
                "Runs server commands programmatically",
                "Calls Bukkit.dispatchCommand(), which executes a server command as if typed in the console. "
                        + "Legitimate for admin tools, but it is also the standard way a backdoor grants itself "
                        + "operator rights (e.g. dispatching 'op <attacker>').",
                "Check which command string is dispatched and whether it can be influenced by chat or network input.", 14));
        r.add(rule("BYTECODE_BUKKIT_CONSOLE_DISPATCH_SERVER", "org/bukkit/Server", Set.of("dispatchCommand"),
                Category.MINECRAFT, Severity.MEDIUM,
                "Runs server commands programmatically",
                "Calls Server.dispatchCommand(), which executes a server command as if typed in the console. "
                        + "Legitimate for admin tools, but it is also the standard way a backdoor grants itself "
                        + "operator rights (e.g. dispatching 'op <attacker>').",
                "Check which command string is dispatched and whether it can be influenced by chat or network input.", 14));
        r.add(prefixMethodRule("BYTECODE_BUKKIT_SET_OP", "org/bukkit/", Set.of("setOp"),
                Category.MINECRAFT, Severity.MEDIUM,
                "Grants or revokes operator status in code",
                "Calls setOp() on a player/offline-player, programmatically changing operator (full-admin) status. "
                        + "Common in rank/permission plugins, but granting op from code — especially to a hard-coded "
                        + "name or in response to a hidden command — is the core of an operator backdoor.",
                "Confirm op is only granted to legitimately authorised players, never a fixed name or external input.", 16));
        r.add(anyOwnerMethodRule("BYTECODE_MC_SESSION_TOKEN", Set.of("getAccessToken"),
                Category.MINECRAFT, Severity.MEDIUM,
                "Reads the Minecraft session access token",
                "Calls getAccessToken(), which on a client retrieves the Minecraft/Microsoft session token. "
                        + "On a client-side mod this is the exact value an account/session stealer exfiltrates; "
                        + "a server plugin has no legitimate reason to read it.",
                "Treat as high risk on client mods — see whether the token is sent over the network.", 20));

        // Fabric/NeoForge (Mojang-mapped) equivalents of the Bukkit console/op sinks above.
        // CAVEAT: these match by name only when the jar ships Mojang ("named") mappings — NeoForge
        // mods, or a Fabric mod built against a Mojmap runtime. A *production* Fabric jar is remapped
        // to intermediary (e.g. Commands#performPrefixedCommand -> net/minecraft/class_2170#method_44252),
        // so these names are absent there. Catching intermediary-mapped Minecraft sinks needs an
        // intermediary->named mapping layer (per Minecraft version) that the engine does not yet have.
        r.add(rule("BYTECODE_MC_COMMAND_DISPATCH", "net/minecraft/commands/Commands",
                Set.of("performPrefixedCommand", "performCommand"),
                Category.MINECRAFT, Severity.MEDIUM,
                "Runs server commands programmatically",
                "Calls Commands.performPrefixedCommand/performCommand, executing a server command from code via a "
                        + "CommandSourceStack. Legitimate for admin tooling, but also the standard way a mod runs "
                        + "arbitrary operator-level commands or grants itself operator rights.",
                "Check which command string is executed and whether it can be influenced by network or chat input.", 14));
        r.add(rule("BYTECODE_MC_SET_OP", "net/minecraft/server/players/PlayerList",
                Set.of("op", "deop"),
                Category.MINECRAFT, Severity.MEDIUM,
                "Grants or revokes operator status in code",
                "Calls PlayerList.op()/deop() to change a player's operator (full-admin) status from code. Common "
                        + "in admin tooling, but granting op from code — especially to a fixed name or in response to "
                        + "a hidden command/endpoint — is the core of an operator backdoor.",
                "Confirm op is only granted to legitimately authorised players, never a fixed name or external input.", 16));

        return r;
    }
}
