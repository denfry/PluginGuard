package dev.pluginguard.engine;

import dev.pluginguard.config.AnalyzerProperties;
import dev.pluginguard.engine.model.ClassFile;
import dev.pluginguard.engine.model.JarEntryInfo;
import dev.pluginguard.engine.model.JarModel;
import dev.pluginguard.engine.model.ResourceFile;
import dev.pluginguard.engine.util.ZipDirectory;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Safely unpacks an uploaded JAR into an in-memory {@link JarModel}, descending into nested
 * {@code .jar} entries up to a configured depth.
 *
 * <p><strong>This never executes or loads any class.</strong> It only reads the ZIP container and
 * retains bytes. A set of guards protects against zip-bombs and resource exhaustion:
 * per-entry and total uncompressed size caps, an entry-count cap, and a per-entry compression-ratio
 * cap. Crucially, those caps are enforced <em>cumulatively across all nesting levels</em>, so a
 * deeply-nested archive cannot multiply the budget. When a guard trips, reading stops gracefully and
 * a note is recorded rather than throwing, so the rest of the report can still be produced.
 */
@Component
public class JarLoader {

    /** Resources larger than this are recorded as entries but their bytes are not retained. */
    private static final long MAX_RETAINED_RESOURCE_BYTES = 4L * 1024 * 1024;

    private final AnalyzerProperties.Limits limits;

    public JarLoader(AnalyzerProperties properties) {
        this.limits = properties.getLimits();
    }

    public JarModel load(String fileName, byte[] data) {
        if (data == null || data.length == 0) {
            throw new AnalysisException("Uploaded file is empty.");
        }
        String sha256 = sha256(data);
        boolean validZip = hasZipMagic(data);

        Accumulator acc = new Accumulator();

        if (!validZip) {
            // Not a real archive — return a shell model; StructureAnalyzer will flag it.
            return new JarModel(fileName, sha256, data.length, false,
                    acc.entries, acc.classes, acc.resources, acc.nestedJars, acc.guardNotes, List.of());
        }

        readArchive(data, "", 0, acc);

        List<String> zipAnomalies = detectZipAnomalies(data, acc);

        return new JarModel(fileName, sha256, data.length, true,
                acc.entries, acc.classes, acc.resources, acc.nestedJars, acc.guardNotes, zipAnomalies);
    }

    /**
     * Compares the names we read sequentially (local file headers, what the recursive descent saw at
     * the top level) against the names the central directory advertises (what the JVM's class loader
     * actually trusts). A mismatch means entries are hidden from one view or the other — a deliberate
     * tampering / hiding technique (e.g. two archives concatenated). Skipped when a resource guard cut
     * the read short, since the streamed set would then be incomplete and the comparison meaningless.
     */
    private List<String> detectZipAnomalies(byte[] data, Accumulator acc) {
        if (acc.stopped) {
            return List.of();
        }
        Optional<Set<String>> central = ZipDirectory.centralDirectoryNames(data);
        if (central.isEmpty()) {
            return List.of();
        }
        Set<String> directory = central.get();
        List<String> notes = new ArrayList<>();

        List<String> hiddenFromScan = difference(directory, acc.topLevelStreamNames);
        if (!hiddenFromScan.isEmpty()) {
            notes.add("ZIP central directory lists " + hiddenFromScan.size() + " entry(ies) not present when "
                    + "reading the archive front-to-back: " + preview(hiddenFromScan) + ". The server's class "
                    + "loader would load these, but a sequential scan cannot see them — a deliberate hiding technique.");
        }
        List<String> onlyStreamed = difference(acc.topLevelStreamNames, directory);
        if (!onlyStreamed.isEmpty()) {
            notes.add("The archive contains " + onlyStreamed.size() + " entry(ies) absent from the ZIP central "
                    + "directory: " + preview(onlyStreamed) + ". These are visible to a sequential reader but "
                    + "ignored by the JVM, which can mislead inspection tools.");
        }
        return notes;
    }

    /** Names in {@code a} but not in {@code b}, ignoring directory entries. */
    private static List<String> difference(Set<String> a, Set<String> b) {
        List<String> out = new ArrayList<>();
        for (String name : a) {
            if (!name.endsWith("/") && !b.contains(name)) {
                out.add(name);
            }
        }
        return out;
    }

    private static String preview(List<String> names) {
        int limit = Math.min(names.size(), 5);
        String shown = String.join(", ", names.subList(0, limit));
        return names.size() > limit ? shown + ", …" : shown;
    }

    /** Mutable state threaded through the recursive descent so guards apply to the whole tree. */
    private static final class Accumulator {
        final List<JarEntryInfo> entries = new ArrayList<>();
        final List<ClassFile> classes = new ArrayList<>();
        final List<ResourceFile> resources = new ArrayList<>();
        final List<String> nestedJars = new ArrayList<>();
        final List<String> guardNotes = new ArrayList<>();
        /** Names read sequentially from the top-level archive, for the central-directory cross-check. */
        final Set<String> topLevelStreamNames = new LinkedHashSet<>();
        long totalUncompressed = 0;
        int entryCount = 0;
        boolean stopped = false;
    }

    /**
     * Reads one ZIP archive's entries into {@code acc}. {@code container} is the jar-chain prefix
     * (e.g. {@code lib.jar!/}); {@code depth} is the current nesting level (0 = top-level).
     */
    private void readArchive(byte[] data, String container, int depth, Accumulator acc) {
        if (acc.stopped) {
            return;
        }
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(data))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                acc.entryCount++;
                if (acc.entryCount > limits.getMaxEntries()) {
                    acc.guardNotes.add("Entry-count guard hit (> " + limits.getMaxEntries()
                            + " entries across all nesting); remaining entries were not analyzed.");
                    acc.stopped = true;
                    break;
                }

                String name = entry.getName();
                if (depth == 0) {
                    acc.topLevelStreamNames.add(name);
                }
                String displayName = container + name;
                if (entry.isDirectory()) {
                    acc.entries.add(new JarEntryInfo(displayName, 0, true));
                    zis.closeEntry();
                    continue;
                }

                long totalRemaining = limits.getMaxTotalUncompressedBytes() - acc.totalUncompressed;
                if (totalRemaining <= 0) {
                    acc.guardNotes.add("Total uncompressed-size guard hit ("
                            + limits.getMaxTotalUncompressedBytes() + " bytes); remaining entries skipped.");
                    acc.stopped = true;
                    break;
                }

                ReadResult read = readBounded(zis, limits.getMaxEntryUncompressedBytes(), totalRemaining);
                acc.totalUncompressed += read.bytes.length;
                if (read.truncated) {
                    acc.guardNotes.add("Entry '" + displayName + "' exceeded the size guard and was truncated.");
                }

                // Best-effort compression-ratio (zip-bomb) check.
                long compressed = entry.getCompressedSize();
                if (compressed > 0 && read.bytes.length / (double) compressed > limits.getMaxCompressionRatio()) {
                    acc.guardNotes.add("Entry '" + displayName + "' has a suspicious compression ratio ("
                            + (read.bytes.length / compressed) + ":1) — possible zip-bomb.");
                }

                acc.entries.add(new JarEntryInfo(displayName, read.bytes.length, false));

                String lower = name.toLowerCase();
                if (lower.endsWith(".class")) {
                    String internalName = name.substring(0, name.length() - ".class".length());
                    acc.classes.add(new ClassFile(internalName, read.bytes, container));
                } else if (lower.endsWith(".jar") || lower.endsWith(".zip") || lower.endsWith(".war")) {
                    acc.nestedJars.add(displayName);
                    if (depth < limits.getMaxNestedJarDepth() && hasZipMagic(read.bytes)) {
                        readArchive(read.bytes, displayName + "!/", depth + 1, acc);
                        if (acc.stopped) {
                            break;
                        }
                    } else if (depth >= limits.getMaxNestedJarDepth()) {
                        acc.guardNotes.add("Nested-jar depth guard hit at '" + displayName
                                + "' (max depth " + limits.getMaxNestedJarDepth() + "); its contents were not analyzed.");
                    }
                    // Also keep the nested archive's own bytes available for magic/entropy checks.
                    retainResource(acc, name, read.bytes, container);
                } else {
                    retainResource(acc, name, read.bytes, container);
                }
                zis.closeEntry();
            }
        } catch (IOException e) {
            acc.guardNotes.add("Archive '" + (container.isEmpty() ? "(root)" : container)
                    + "' could not be fully read: " + e.getMessage());
        }
    }

    private void retainResource(Accumulator acc, String name, byte[] bytes, String container) {
        if (bytes.length <= MAX_RETAINED_RESOURCE_BYTES) {
            acc.resources.add(new ResourceFile(name, bytes, container));
        }
    }

    private record ReadResult(byte[] bytes, boolean truncated) {
    }

    /** Reads an entry's bytes, stopping at {@code min(perEntryMax, totalRemaining)}. */
    private ReadResult readBounded(InputStream in, long perEntryMax, long totalRemaining) throws IOException {
        long cap = Math.min(perEntryMax, totalRemaining);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        long read = 0;
        int n;
        boolean truncated = false;
        while ((n = in.read(buf)) != -1) {
            if (read + n > cap) {
                int allowed = (int) (cap - read);
                if (allowed > 0) {
                    out.write(buf, 0, allowed);
                }
                truncated = true;
                break;
            }
            out.write(buf, 0, n);
            read += n;
        }
        return new ReadResult(out.toByteArray(), truncated);
    }

    private static boolean hasZipMagic(byte[] data) {
        // Local file header (PK\x03\x04), empty archive (PK\x05\x06) or spanned (PK\x07\x08).
        return data.length >= 4 && data[0] == 0x50 && data[1] == 0x4B
                && (data[2] == 0x03 || data[2] == 0x05 || data[2] == 0x07);
    }

    private static String sha256(byte[] data) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
