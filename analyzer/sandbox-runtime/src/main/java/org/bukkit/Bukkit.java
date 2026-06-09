package org.bukkit;

import org.bukkit.plugin.PluginManager;
import org.bukkit.scheduler.BukkitScheduler;

import java.util.logging.Logger;

/** Static accessor mirroring {@code org.bukkit.Bukkit}; the harness sets the active mock server. */
public final class Bukkit {

    private static Server server;

    private Bukkit() {
    }

    public static void setServer(Server s) {
        server = s;
    }

    public static Server getServer() {
        return server;
    }

    public static Logger getLogger() {
        return server != null ? server.getLogger() : Logger.getLogger("Sandbox");
    }

    public static PluginManager getPluginManager() {
        return server != null ? server.getPluginManager() : null;
    }

    public static BukkitScheduler getScheduler() {
        return server != null ? server.getScheduler() : null;
    }

    public static String getName() {
        return server != null ? server.getName() : "PluginGuardSandbox";
    }

    public static String getVersion() {
        return server != null ? server.getVersion() : "sandbox";
    }
}
