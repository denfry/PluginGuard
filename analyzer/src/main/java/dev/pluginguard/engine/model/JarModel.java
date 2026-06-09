package dev.pluginguard.engine.model;

import java.util.List;
import java.util.Optional;

/**
 * In-memory, parse-only representation of an uploaded JAR, produced by
 * {@link dev.pluginguard.engine.JarLoader}. No class here is ever loaded or executed.
 *
 * @param fileName    original uploaded filename
 * @param sha256      SHA-256 of the uploaded bytes
 * @param sizeBytes   uploaded (compressed) file size
 * @param validZip    whether the bytes started with the ZIP local-file-header magic ({@code PK\x03\x04})
 * @param entries     metadata for every entry encountered
 * @param classes     {@code .class} entries with retained bytes
 * @param resources   non-class entries with retained bytes
 * @param nestedJars  names of nested {@code .jar} entries (not recursively analyzed in this version)
 * @param guardNotes  notes about any zip-bomb / resource guard that was triggered
 */
public record JarModel(
        String fileName,
        String sha256,
        long sizeBytes,
        boolean validZip,
        List<JarEntryInfo> entries,
        List<ClassFile> classes,
        List<ResourceFile> resources,
        List<String> nestedJars,
        List<String> guardNotes) {

    /** Finds a resource by exact entry path. */
    public Optional<ResourceFile> resource(String name) {
        return resources.stream().filter(r -> r.name().equals(name)).findFirst();
    }

    /** Total uncompressed bytes across all entries. */
    public long totalUncompressedBytes() {
        return entries.stream().mapToLong(JarEntryInfo::uncompressedSize).sum();
    }
}
