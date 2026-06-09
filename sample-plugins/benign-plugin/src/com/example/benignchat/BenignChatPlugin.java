package com.example.benignchat;

/**
 * Sample fixture — a deliberately well-behaved "plugin" main class.
 *
 * <p>Kept dependency-free (does not extend Bukkit's JavaPlugin) so it compiles with a plain JDK.
 * PluginGuard treats it as a plugin because plugin.yml is present and names this class as main.
 */
public class BenignChatPlugin {

    private final UpdateChecker updateChecker = new UpdateChecker();

    public void onEnable() {
        // Normal plugin startup would register listeners and commands here.
        updateChecker.latestVersion();
    }
}
