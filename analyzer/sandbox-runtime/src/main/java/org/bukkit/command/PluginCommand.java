package org.bukkit.command;

/** A plugin-declared command. The harness hands these back from {@code JavaPlugin.getCommand}. */
public class PluginCommand extends Command {

    private CommandExecutor executor;

    public PluginCommand(String name) {
        super(name);
    }

    public void setExecutor(CommandExecutor executor) {
        this.executor = executor;
    }

    public CommandExecutor getExecutor() {
        return executor;
    }

    public void setTabCompleter(Object completer) {
        // no-op: tab completion is irrelevant to behavior capture
    }
}
