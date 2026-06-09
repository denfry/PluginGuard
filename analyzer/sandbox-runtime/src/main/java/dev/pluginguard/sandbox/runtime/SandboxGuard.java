package dev.pluginguard.sandbox.runtime;

/**
 * Process-wide facade the sandbox runtime records behavior through. The JVM agent and the
 * {@link InstrumentingClassLoader} rewrite the plugin's dangerous call sites to invoke
 * {@link #mark(String)} just before the real call, and the {@link SandboxSecurityManager} and
 * {@link MockBukkitHarness} call the typed helpers directly.
 *
 * <p>All state is static because the instrumented bytecode can only reach a static method and there
 * is exactly one sandbox run per JVM.
 */
public final class SandboxGuard {

    /**
     * Separator between the event type and target in the single string an instrumented call passes.
     * A pipe is safe: it never occurs in a fully-qualified {@code owner.name} (which uses {@code .},
     * {@code /} and {@code $}).
     */
    static final char SEP = '|';

    private static volatile BehaviorLog log = new BehaviorLog();
    private static volatile ClassLoader pluginLoader;

    private SandboxGuard() {
    }

    /** Installs the behavior sink (file-backed inside the container, memory-only in tests). */
    public static void install(BehaviorLog newLog) {
        log = newLog;
    }

    public static BehaviorLog log() {
        return log;
    }

    /** Records the classloader that loaded the untrusted plugin, so the SM can attribute callers. */
    public static void setPluginLoader(ClassLoader loader) {
        pluginLoader = loader;
    }

    public static ClassLoader pluginLoader() {
        return pluginLoader;
    }

    /**
     * Entry point the instrumented bytecode calls. The argument is {@code "TYPE|target"} prepared at
     * transform time; the action itself is allowed to proceed (the SecurityManager / container is
     * what blocks the effect), so this only records the attempt.
     */
    public static void mark(String encoded) {
        if (encoded == null) {
            return;
        }
        int i = encoded.indexOf(SEP);
        String type = i < 0 ? encoded : encoded.substring(0, i);
        String target = i < 0 ? null : encoded.substring(i + 1);
        record(type, target, "observed at an instrumented call site", null, false);
    }

    public static void record(String type, String target, String detail, String source, boolean blocked) {
        log.record(new BehaviorEvent(type, target, detail, source, blocked));
    }

    /** Convenience for the harness lifecycle trail. */
    public static void lifecycle(String stage, String detail) {
        record("LIFECYCLE", stage, detail, null, false);
    }
}
