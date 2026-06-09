package dev.pluginguard.sandbox.runtime;

import org.bukkit.scheduler.BukkitScheduler;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Runs submitted tasks once, synchronously, on the harness thread. Async/repeating/delayed variants
 * all collapse to a single immediate run so the plugin's scheduled code is still observed, without
 * the harness having to wait on real timers. Task exceptions are swallowed (and recorded).
 */
final class MockScheduler implements BukkitScheduler {

    private final AtomicInteger ids = new AtomicInteger(1);

    private int run(Runnable task) {
        SandboxGuard.lifecycle("scheduledTask", task == null ? null : task.getClass().getName());
        if (task != null) {
            try {
                task.run();
            } catch (Throwable t) {
                SandboxGuard.record("ERROR", "scheduledTask", t.toString(), null, false);
            }
        }
        return ids.getAndIncrement();
    }

    @Override public int scheduleSyncDelayedTask(Object plugin, Runnable task) { return run(task); }
    @Override public int scheduleSyncRepeatingTask(Object plugin, Runnable task, long delay, long period) { return run(task); }
    @Override public void runTask(Object plugin, Runnable task) { run(task); }
    @Override public void runTaskAsynchronously(Object plugin, Runnable task) { run(task); }
    @Override public void runTaskLater(Object plugin, Runnable task, long delay) { run(task); }
    @Override public void cancelTasks(Object plugin) { /* nothing is actually scheduled */ }
}
