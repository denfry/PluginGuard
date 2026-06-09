package dev.pluginguard.engine.model;

/**
 * Lightweight record of one entry inside the archive, kept for structure analysis even when the
 * entry's bytes are not retained (e.g. very large non-class resources).
 *
 * @param name             full entry path inside the JAR
 * @param uncompressedSize uncompressed size in bytes (as read, after guard enforcement)
 * @param directory        whether the entry is a directory
 */
public record JarEntryInfo(String name, long uncompressedSize, boolean directory) {
}
