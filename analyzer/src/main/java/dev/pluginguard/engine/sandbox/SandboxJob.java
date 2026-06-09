package dev.pluginguard.engine.sandbox;

import java.util.List;

/**
 * Input for one sandbox run: the uploaded plugin bytes plus what the harness needs to drive it.
 *
 * @param id        the report id (also the per-run work directory name)
 * @param jarBytes  the uploaded plugin jar
 * @param fileName  original filename (for logs)
 * @param mainClass declared plugin main class, or {@code null} (the harness reads plugin.yml then)
 * @param commands  declared command names to trigger after onEnable
 */
public record SandboxJob(
        String id,
        byte[] jarBytes,
        String fileName,
        String mainClass,
        List<String> commands) {
}
