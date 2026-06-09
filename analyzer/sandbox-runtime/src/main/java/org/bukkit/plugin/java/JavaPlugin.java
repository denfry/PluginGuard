package org.bukkit.plugin.java;

import org.bukkit.Server;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.command.PluginCommand;
import org.bukkit.configuration.file.FileConfiguration;
import org.bukkit.event.Listener;
import org.bukkit.plugin.Plugin;

import java.io.File;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Mock base class for Minecraft plugins. A plugin's {@code extends JavaPlugin} links against this,
 * and the harness drives its real {@code onLoad}/{@code onEnable}/command/{@code onDisable} code.
 * It implements {@link Plugin}, {@link CommandExecutor} and {@link Listener} so the common
 * {@code registerEvents(this, this)} / {@code getCommand(x).setExecutor(this)} patterns link.
 */
public abstract class JavaPlugin implements Plugin, CommandExecutor, Listener {

    private Server server;
    private File dataFolder;
    private String pluginName = "SandboxPlugin";
    private Logger logger = Logger.getLogger("SandboxPlugin");
    private final FileConfiguration config = new FileConfiguration();
    private final Map<String, PluginCommand> commands = new HashMap<>();
    private boolean enabled;

    /** Wired by the harness before lifecycle calls. Not part of the real API. */
    public final void initSandbox(Server server, File dataFolder, String name) {
        this.server = server;
        this.dataFolder = dataFolder;
        this.pluginName = name;
        this.logger = Logger.getLogger(name);
    }

    public final void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    @Override public void onLoad() { }
    @Override public void onEnable() { }
    @Override public void onDisable() { }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        return false;
    }

    @Override public final String getName() { return pluginName; }
    @Override public final Logger getLogger() { return logger; }
    @Override public final Server getServer() { return server; }
    @Override public final File getDataFolder() { return dataFolder; }
    @Override public final boolean isEnabled() { return enabled; }

    public final FileConfiguration getConfig() { return config; }
    public void saveDefaultConfig() { }
    public void saveConfig() { }
    public void reloadConfig() { }
    public void saveResource(String resourcePath, boolean replace) { }

    /** Returns (creating on demand) a command handle the plugin can attach an executor to. */
    public PluginCommand getCommand(String name) {
        return commands.computeIfAbsent(name, PluginCommand::new);
    }
}
