package dev.pluginguard.sandbox.runtime;

import java.lang.instrument.Instrumentation;

/**
 * JVM agent installed in the container via {@code -javaagent:runtime.jar}. It registers the
 * {@link GuardTransformer} (so dangerous call sites are logged even in classes the harness's
 * {@link InstrumentingClassLoader} never sees — e.g. dynamically generated ones) and installs the
 * {@link SandboxSecurityManager} as the enforcing boundary.
 *
 * <p>The security manager is only installable when the container launches the JVM with
 * {@code -Djava.security.manager=allow}; if that flag is absent the agent records a note and relies
 * on the container's own isolation. In-process tests never attach this agent, so they never install
 * a global security manager.
 */
public final class SandboxAgent {

    private SandboxAgent() {
    }

    public static void premain(String agentArgs, Instrumentation inst) {
        install(inst);
    }

    public static void agentmain(String agentArgs, Instrumentation inst) {
        install(inst);
    }

    private static void install(Instrumentation inst) {
        if (inst != null) {
            inst.addTransformer(new GuardTransformer(), true);
        }
        installSecurityManager();
    }

    @SuppressWarnings({"removal", "deprecation"})
    private static void installSecurityManager() {
        try {
            System.setSecurityManager(new SandboxSecurityManager());
            SandboxGuard.lifecycle("securityManager", "installed");
        } catch (Throwable t) {
            SandboxGuard.record("LIFECYCLE", "securityManager",
                    "unavailable (need -Djava.security.manager=allow): " + t, null, false);
        }
    }
}
