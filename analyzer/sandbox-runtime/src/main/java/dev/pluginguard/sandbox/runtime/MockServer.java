package dev.pluginguard.sandbox.runtime;

import org.bukkit.Server;
import org.bukkit.command.CommandSender;
import org.bukkit.plugin.PluginManager;
import org.bukkit.scheduler.BukkitScheduler;

import java.util.Collections;
import java.util.List;
import java.util.logging.Logger;

/** A minimal stand-in for the Paper/Bukkit server the plugin runs against in the sandbox. */
final class MockServer implements Server {

    private final Logger logger = Logger.getLogger("PluginGuardSandbox");
    private final PluginManager pluginManager = new MockPluginManager();
    private final BukkitScheduler scheduler = new MockScheduler();
    private final CommandSender console = new MockCommandSender();

    @Override public String getName() { return "PluginGuardSandbox"; }
    @Override public String getVersion() { return "1.21-SANDBOX"; }
    @Override public String getBukkitVersion() { return "1.21-R0.1-SANDBOX"; }
    @Override public Logger getLogger() { return logger; }
    @Override public PluginManager getPluginManager() { return pluginManager; }
    @Override public BukkitScheduler getScheduler() { return scheduler; }
    @Override public CommandSender getConsoleSender() { return console; }
    @Override public List<?> getOnlinePlayers() { return Collections.emptyList(); }
    @Override public int getPort() { return 25565; }

    @Override
    public int broadcastMessage(String message) {
        SandboxGuard.record("OUTPUT", null, message, "broadcast", false);
        return 0;
    }
}
