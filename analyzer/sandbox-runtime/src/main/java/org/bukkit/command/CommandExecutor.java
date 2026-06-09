package org.bukkit.command;

/** Handles a command. {@code JavaPlugin} implements this, as in the real Bukkit API. */
public interface CommandExecutor {

    boolean onCommand(CommandSender sender, Command command, String label, String[] args);
}
