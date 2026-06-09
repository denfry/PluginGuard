package dev.pluginguard.engine.model;

import java.nio.charset.StandardCharsets;

/** A non-class file entry (e.g. {@code plugin.yml}, {@code config.yml}) and its bytes. */
public record ResourceFile(String name, byte[] bytes) {

    /** Decodes the resource as UTF-8 text (lossy for binary content). */
    public String text() {
        return new String(bytes, StandardCharsets.UTF_8);
    }
}
