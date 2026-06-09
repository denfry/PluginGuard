package org.bukkit.plugin;

import org.bukkit.event.Event;
import org.bukkit.event.Listener;

/** Subset of the Bukkit plugin manager. The mock records registrations and event dispatches. */
public interface PluginManager {

    void registerEvents(Listener listener, Plugin plugin);

    void callEvent(Event event);

    void disablePlugin(Plugin plugin);

    boolean isPluginEnabled(String name);
}
