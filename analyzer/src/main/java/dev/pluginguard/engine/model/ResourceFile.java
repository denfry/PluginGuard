package dev.pluginguard.engine.model;

import java.nio.charset.StandardCharsets;

/**
 * A non-class file entry (e.g. {@code plugin.yml}, {@code config.yml}) and its bytes.
 *
 * @param name      entry path inside its own archive (used for type checks and resource lookups)
 * @param bytes     raw entry bytes
 * @param container jar-chain this resource came from for nested archives
 *                  (e.g. {@code bundled/lib.jar!/}), or {@code ""} for the top-level JAR
 */
public record ResourceFile(String name, byte[] bytes, String container) {

    public ResourceFile(String name, byte[] bytes) {
        this(name, bytes, "");
    }

    /** Decodes the resource as UTF-8 text (lossy for binary content). */
    public String text() {
        return new String(bytes, StandardCharsets.UTF_8);
    }

    /** Human-readable location including the nested jar-chain, e.g. {@code lib.jar!/config.yml}. */
    public String displayName() {
        return container == null || container.isEmpty() ? name : container + name;
    }

    /** Whether this resource lives inside a nested archive rather than the top-level JAR. */
    public boolean nested() {
        return container != null && !container.isEmpty();
    }
}
