package dev.pluginguard.engine.model;

/**
 * A bundled / shaded dependency discovered inside the JAR.
 *
 * @param name    artifact or library name (best-effort, e.g. {@code gson} or {@code com.google.gson})
 * @param version detected version, or {@code null} if unknown
 * @param source  how it was detected (e.g. {@code pom.properties}, {@code nested-jar}, {@code package})
 */
public record Dependency(String name, String version, String source) {
}
