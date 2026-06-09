package dev.pluginguard.sandbox.runtime;

import org.bukkit.event.Event;
import org.bukkit.event.Listener;
import org.bukkit.plugin.Plugin;
import org.bukkit.plugin.PluginManager;

/** Records the plugin's listener registrations and event dispatches without real event routing. */
final class MockPluginManager implements PluginManager {

    @Override
    public void registerEvents(Listener listener, Plugin plugin) {
        SandboxGuard.lifecycle("registerEvents", listener == null ? null : listener.getClass().getName());
    }

    @Override
    public void callEvent(Event event) {
        SandboxGuard.lifecycle("callEvent", event == null ? null : event.getEventName());
    }

    @Override
    public void disablePlugin(Plugin plugin) {
        SandboxGuard.lifecycle("disablePlugin", plugin == null ? null : plugin.getName());
    }

    @Override
    public boolean isPluginEnabled(String name) {
        return false;
    }
}
