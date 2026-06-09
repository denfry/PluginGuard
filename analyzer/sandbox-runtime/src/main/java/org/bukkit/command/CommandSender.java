package org.bukkit.command;

/** Recipient of command output / messages. Mirrors the subset of the Bukkit API plugins use. */
public interface CommandSender {

    void sendMessage(String message);

    String getName();

    boolean hasPermission(String permission);

    boolean isOp();
}
