package dev.pluginguard.engine.sandbox;

/**
 * Executes a plugin in an isolated environment and returns the observed behavior. The only
 * implementation is {@link DockerSandboxRunner}; the interface keeps the orchestration testable and
 * leaves room for other isolation backends.
 */
public interface SandboxRunner {

    /** Short runtime name surfaced in the report (e.g. {@code docker}). */
    String name();

    /** Whether this runner can run right now (runtime present, agent jar resolvable). */
    boolean isAvailable();

    /** Runs the job, never throwing: failures map to a {@code FAILED}/{@code UNAVAILABLE} outcome. */
    SandboxOutcome run(SandboxJob job);
}
