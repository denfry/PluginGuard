package demo;

import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.plugin.java.JavaPlugin;

/**
 * A harmless synthetic plugin used to exercise the harness end-to-end. Its {@code onEnable} performs
 * a reflective lookup (which the instrumenting loader records as a REFLECTION behavior event) and
 * its command handler resolves a scheduler task — all on benign, real JDK classes. It lives in a
 * non-{@code dev.pluginguard.sandbox.runtime} package so the instrumenter does not skip it.
 */
public class DemoPlugin extends JavaPlugin {

    @Override
    public void onEnable() {
        getLogger().info("DemoPlugin enabling");
        try {
            // Harmless: resolves a core JDK class. The point is that the call site is instrumented.
            Class.forName("java.lang.String");
        } catch (ClassNotFoundException ignored) {
            // unreachable for a core class
        }
    }

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        sender.sendMessage("demo ran " + command.getName());
        return true;
    }
}
