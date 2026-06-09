package org.bukkit.scheduler;

/**
 * Subset of the Bukkit scheduler. The mock runs submitted {@link Runnable}s once, synchronously,
 * so a plugin that does its real work from a scheduled task still has that code observed.
 */
public interface BukkitScheduler {

    int scheduleSyncDelayedTask(Object plugin, Runnable task);

    int scheduleSyncRepeatingTask(Object plugin, Runnable task, long delay, long period);

    void runTask(Object plugin, Runnable task);

    void runTaskAsynchronously(Object plugin, Runnable task);

    void runTaskLater(Object plugin, Runnable task, long delay);

    void cancelTasks(Object plugin);
}
