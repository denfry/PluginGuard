package org.bukkit.plugin;

import org.bukkit.Server;

import java.io.File;
import java.util.logging.Logger;

/** The lean subset of the Bukkit {@code Plugin} interface the mock harness relies on. */
public interface Plugin {

    String getName();

    Logger getLogger();

    Server getServer();

    File getDataFolder();

    boolean isEnabled();

    void onLoad();

    void onEnable();

    void onDisable();
}
