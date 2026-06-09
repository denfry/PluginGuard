package dev.pluginguard.sandbox.runtime;

import java.security.Permission;

/**
 * The actual "log-and-block" boundary for effects the JDK routes through access checks: process
 * execution, outbound/inbound sockets, {@code System.exit}, native library loading, file writes and
 * any attempt to remove the security manager. A check is only enforced when the call was initiated
 * by the plugin's classloader (determined from {@link #getClassContext()}), so the harness's own
 * bootstrap and the JDK run unhindered.
 *
 * <p>{@link SecurityManager} is deprecated for removal, but it remains the most faithful in-JVM
 * mechanism to both observe and deny these actions; the container's seccomp/network/read-only
 * isolation is the outer, independent backstop.
 */
@SuppressWarnings({"removal", "deprecation"})
public final class SandboxSecurityManager extends SecurityManager {

    /** Whether {@code context} contains any frame loaded by (a descendant of) the plugin loader. */
    static boolean isPluginInitiated(Class<?>[] context, ClassLoader pluginLoader) {
        if (pluginLoader == null || context == null) {
            return false;
        }
        for (Class<?> c : context) {
            for (ClassLoader cl = c.getClassLoader(); cl != null; cl = cl.getParent()) {
                if (cl == pluginLoader) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean pluginInitiated() {
        return isPluginInitiated(getClassContext(), SandboxGuard.pluginLoader());
    }

    private void deny(String type, String target) {
        SandboxGuard.record(type, target, "blocked by sandbox SecurityManager", null, true);
        throw new SandboxBlockedException("Sandbox blocked " + type + ": " + target);
    }

    @Override
    public void checkExec(String cmd) {
        if (pluginInitiated()) {
            deny("PROCESS_EXEC", cmd);
        }
    }

    @Override
    public void checkConnect(String host, int port) {
        if (pluginInitiated()) {
            deny("NETWORK_CONNECT", host + ":" + port);
        }
    }

    @Override
    public void checkConnect(String host, int port, Object context) {
        checkConnect(host, port);
    }

    @Override
    public void checkListen(int port) {
        if (pluginInitiated()) {
            deny("NETWORK_LISTEN", String.valueOf(port));
        }
    }

    @Override
    public void checkAccept(String host, int port) {
        if (pluginInitiated()) {
            deny("NETWORK_LISTEN", host + ":" + port);
        }
    }

    @Override
    public void checkExit(int status) {
        if (pluginInitiated()) {
            deny("JVM_EXIT", String.valueOf(status));
        }
    }

    @Override
    public void checkLink(String lib) {
        if (pluginInitiated()) {
            deny("LOAD_LIBRARY", lib);
        }
    }

    @Override
    public void checkWrite(String file) {
        if (pluginInitiated()) {
            deny("FILE_WRITE", file);
        }
    }

    @Override
    public void checkDelete(String file) {
        if (pluginInitiated()) {
            deny("FILE_WRITE", file);
        }
    }

    @Override
    public void checkPermission(Permission perm) {
        // Stop the plugin from uninstalling the sandbox; allow everything else (reads, properties)
        // so we do not flood the log or break the JVM. The transformer covers the rest.
        if (perm instanceof RuntimePermission && "setSecurityManager".equals(perm.getName()) && pluginInitiated()) {
            deny("SECURITY_MANAGER", "setSecurityManager");
        }
    }

    @Override
    public void checkPermission(Permission perm, Object context) {
        checkPermission(perm);
    }
}
