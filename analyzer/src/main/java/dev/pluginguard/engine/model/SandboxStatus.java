package dev.pluginguard.engine.model;

/**
 * Lifecycle of the optional Phase&nbsp;3 dynamic sandbox run for a report. The static analysis is
 * always synchronous; the sandbox (when enabled) is an asynchronous job whose status the
 * {@code GET /api/scan/{id}} endpoint surfaces as it progresses.
 */
public enum SandboxStatus {
    /** The sandbox feature is turned off (the default). */
    DISABLED,
    /** Enabled and queued, not yet started. */
    PENDING,
    /** The container is currently executing the plugin. */
    RUNNING,
    /** Finished; dynamic findings are available. */
    COMPLETED,
    /** Enabled but skipped for this file (e.g. no plugin main class to drive). */
    SKIPPED,
    /** The runtime (Docker) was unavailable, so no dynamic analysis was performed. */
    UNAVAILABLE,
    /** The run started but failed; partial or no results. */
    FAILED
}
