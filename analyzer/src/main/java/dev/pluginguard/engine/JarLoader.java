package dev.pluginguard.engine;

import dev.pluginguard.config.AnalyzerProperties;
import dev.pluginguard.engine.model.ClassFile;
import dev.pluginguard.engine.model.JarEntryInfo;
import dev.pluginguard.engine.model.JarModel;
import dev.pluginguard.engine.model.ResourceFile;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * Safely unpacks an uploaded JAR into an in-memory {@link JarModel}.
 *
 * <p><strong>This never executes or loads any class.</strong> It only reads the ZIP container and
 * retains bytes. A set of guards protects against zip-bombs and resource exhaustion:
 * per-entry and total uncompressed size caps, an entry-count cap, and a per-entry compression-ratio
 * cap. When a guard trips, reading stops gracefully and a note is recorded rather than throwing,
 * so the rest of the report can still be produced.
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

        List<JarEntryInfo> entries = new ArrayList<>();
        List<ClassFile> classes = new ArrayList<>();
        List<ResourceFile> resources = new ArrayList<>();
        List<String> nestedJars = new ArrayList<>();
        List<String> guardNotes = new ArrayList<>();

        if (!validZip) {
            // Not a real archive — return a shell model; StructureAnalyzer will flag it.
            return new JarModel(fileName, sha256, data.length, false,
                    entries, classes, resources, nestedJars, guardNotes);
        }

        long totalUncompressed = 0;
        int entryCount = 0;

        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(data))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                entryCount++;
                if (entryCount > limits.getMaxEntries()) {
                    guardNotes.add("Entry-count guard hit (> " + limits.getMaxEntries()
                            + " entries); remaining entries were not analyzed.");
                    break;
                }

                String name = entry.getName();
                if (entry.isDirectory()) {
                    entries.add(new JarEntryInfo(name, 0, true));
                    zis.closeEntry();
                    continue;
                }

                long totalRemaining = limits.getMaxTotalUncompressedBytes() - totalUncompressed;
                if (totalRemaining <= 0) {
                    guardNotes.add("Total uncompressed-size guard hit ("
                            + limits.getMaxTotalUncompressedBytes() + " bytes); remaining entries skipped.");
                    break;
                }

                ReadResult read = readBounded(zis, limits.getMaxEntryUncompressedBytes(), totalRemaining);
                totalUncompressed += read.bytes.length;
                if (read.truncated) {
                    guardNotes.add("Entry '" + name + "' exceeded the size guard and was truncated.");
                }

                // Best-effort compression-ratio (zip-bomb) check.
                long compressed = entry.getCompressedSize();
                if (compressed > 0 && read.bytes.length / (double) compressed > limits.getMaxCompressionRatio()) {
                    guardNotes.add("Entry '" + name + "' has a suspicious compression ratio ("
                            + (read.bytes.length / compressed) + ":1) — possible zip-bomb.");
                }

                entries.add(new JarEntryInfo(name, read.bytes.length, false));

                String lower = name.toLowerCase();
                if (lower.endsWith(".class")) {
                    String internalName = name.substring(0, name.length() - ".class".length());
                    classes.add(new ClassFile(internalName, read.bytes));
                } else if (lower.endsWith(".jar")) {
                    nestedJars.add(name);
                } else if (read.bytes.length <= MAX_RETAINED_RESOURCE_BYTES) {
                    resources.add(new ResourceFile(name, read.bytes));
                }
                zis.closeEntry();
            }
        } catch (IOException e) {
            guardNotes.add("Archive could not be fully read: " + e.getMessage());
        }

        return new JarModel(fileName, sha256, data.length, true,
                entries, classes, resources, nestedJars, guardNotes);
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
