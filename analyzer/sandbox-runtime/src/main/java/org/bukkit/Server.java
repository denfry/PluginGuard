package org.bukkit;

import org.bukkit.command.CommandSender;
import org.bukkit.plugin.PluginManager;
import org.bukkit.scheduler.BukkitScheduler;

import java.util.List;
import java.util.logging.Logger;

/** The lean subset of the Bukkit {@code Server} interface the mock harness provides. */
public interface Server {

    String getName();

    String getVersion();

    String getBukkitVersion();

    Logger getLogger();

    PluginManager getPluginManager();

    BukkitScheduler getScheduler();

    CommandSender getConsoleSender();

    List<?> getOnlinePlayers();

    int getPort();

    int broadcastMessage(String message);
}
