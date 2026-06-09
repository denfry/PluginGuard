package dev.pluginguard.engine.util;

import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;

/**
 * Parses a ZIP file's <em>central directory</em> directly from raw bytes, returning the set of entry
 * names the directory advertises.
 *
 * <p>This exists to catch a class of tampering that a streaming reader cannot see. A
 * {@link java.util.zip.ZipInputStream} reads <em>local file headers</em> sequentially from the front
 * of the archive, whereas the JVM's class loader (and {@code java.util.zip.ZipFile}) trust the
 * <em>central directory</em> at the end. When the two disagree — for example two archives
 * concatenated so the directory points at a hidden set of entries — code that the server actually
 * loads can be invisible to a front-to-back scan. Comparing the two name sets surfaces the desync.
 *
 * <p>The parser is read-only and defensively bounded: it never allocates based on attacker-controlled
 * sizes beyond the entry count the directory declares, and it gives up gracefully (returning an empty
 * {@link Optional}) on anything it cannot understand — truncation, ZIP64, or a missing directory — so
 * a malformed archive degrades to "could not compare" rather than a false anomaly or an exception.
 */
public final class ZipDirectory {

    private static final int EOCD_SIGNATURE = 0x06054b50;
    private static final int CENTRAL_FILE_HEADER_SIGNATURE = 0x02014b50;
    private static final int EOCD_MIN_SIZE = 22;
    /** Max ZIP comment length, so the EOCD can sit at most this far from the end. */
    private static final int MAX_COMMENT = 0xFFFF;
    /** Refuse to trust a directory that claims an absurd number of entries. */
    private static final int MAX_ENTRIES = 200_000;

    private ZipDirectory() {
    }

    /**
     * Returns the entry names listed in the archive's central directory, or empty if it could not be
     * parsed (truncated, ZIP64, or no directory present).
     */
    public static Optional<Set<String>> centralDirectoryNames(byte[] data) {
        if (data == null || data.length < EOCD_MIN_SIZE) {
            return Optional.empty();
        }
        int eocd = findEocd(data);
        if (eocd < 0) {
            return Optional.empty();
        }

        int totalEntries = u16(data, eocd + 10);
        long cdSize = u32(data, eocd + 12);
        long cdOffset = u32(data, eocd + 16);

        // ZIP64 sentinels — out of scope; signal "cannot compare" rather than guessing.
        if (totalEntries == 0xFFFF || cdSize == 0xFFFFFFFFL || cdOffset == 0xFFFFFFFFL) {
            return Optional.empty();
        }
        if (totalEntries > MAX_ENTRIES || cdOffset < 0 || cdOffset >= data.length) {
            return Optional.empty();
        }

        Set<String> names = new LinkedHashSet<>();
        int pos = (int) cdOffset;
        for (int i = 0; i < totalEntries; i++) {
            if (pos + 46 > data.length || (int) u32(data, pos) != CENTRAL_FILE_HEADER_SIGNATURE) {
                return Optional.empty(); // directory is shorter/different than advertised
            }
            int nameLen = u16(data, pos + 28);
            int extraLen = u16(data, pos + 30);
            int commentLen = u16(data, pos + 32);
            int nameStart = pos + 46;
            if (nameStart + nameLen > data.length) {
                return Optional.empty();
            }
            names.add(new String(data, nameStart, nameLen, java.nio.charset.StandardCharsets.UTF_8));
            pos = nameStart + nameLen + extraLen + commentLen;
        }
        return Optional.of(names);
    }

    /** Scans backwards for the last End Of Central Directory record. */
    private static int findEocd(byte[] data) {
        int minStart = Math.max(0, data.length - EOCD_MIN_SIZE - MAX_COMMENT);
        for (int i = data.length - EOCD_MIN_SIZE; i >= minStart; i--) {
            if ((int) u32(data, i) == EOCD_SIGNATURE) {
                return i;
            }
        }
        return -1;
    }

    private static int u16(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8);
    }

    private static long u32(byte[] b, int off) {
        return (b[off] & 0xFFL) | ((b[off + 1] & 0xFFL) << 8)
                | ((b[off + 2] & 0xFFL) << 16) | ((b[off + 3] & 0xFFL) << 24);
    }
}
