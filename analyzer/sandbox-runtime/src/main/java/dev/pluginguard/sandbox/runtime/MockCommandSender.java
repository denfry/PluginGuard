package dev.pluginguard.sandbox.runtime;

import org.bukkit.command.CommandSender;

/**
 * Console-like sender used to trigger commands. Grants permissions and op so permission-gated code
 * paths actually execute (and get observed); messages are recorded but otherwise discarded.
 */
final class MockCommandSender implements CommandSender {

    @Override
    public void sendMessage(String message) {
        SandboxGuard.record("OUTPUT", null, message, "console", false);
    }

    @Override
    public String getName() {
        return "CONSOLE";
    }

    @Override
    public boolean hasPermission(String permission) {
        return true;
    }

    @Override
    public boolean isOp() {
        return true;
    }
}
