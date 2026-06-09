package dev.pluginguard.engine.util;

/**
 * Recognises file-format magic numbers from raw bytes, independent of any file extension. Used to
 * catch executables and archives hidden under an innocent-looking name (a {@code .png} that is
 * really a class, a {@code .dat} that is really a Windows {@code .exe}, …).
 */
public final class Magic {

    private Magic() {
    }

    public enum Kind {
        JAVA_CLASS("Java class"),
        ZIP_ARCHIVE("ZIP/JAR archive"),
        WINDOWS_PE("Windows executable (PE/.exe/.dll)"),
        ELF_BINARY("Linux/Unix executable (ELF)"),
        MACH_O("macOS executable (Mach-O)"),
        GZIP("gzip stream"),
        NONE("");

        private final String label;

        Kind(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }
    }

    public static Kind detect(byte[] b) {
        return detectAt(b, 0);
    }

    /** Detects the magic at a given offset (used when scanning for an embedded signature). */
    public static Kind detectAt(byte[] b, int off) {
        if (b == null || off < 0 || off + 4 > b.length) {
            return Kind.NONE;
        }
        if (u(b[off]) == 0xCA && u(b[off + 1]) == 0xFE && u(b[off + 2]) == 0xBA && u(b[off + 3]) == 0xBE) {
            return Kind.JAVA_CLASS;
        }
        if (u(b[off]) == 0x50 && u(b[off + 1]) == 0x4B
                && (u(b[off + 2]) == 0x03 || u(b[off + 2]) == 0x05 || u(b[off + 2]) == 0x07)) {
            return Kind.ZIP_ARCHIVE;
        }
        if (u(b[off]) == 0x4D && u(b[off + 1]) == 0x5A) { // "MZ"
            return Kind.WINDOWS_PE;
        }
        if (u(b[off]) == 0x7F && u(b[off + 1]) == 0x45 && u(b[off + 2]) == 0x4C && u(b[off + 3]) == 0x46) { // \x7fELF
            return Kind.ELF_BINARY;
        }
        if (u(b[off]) == 0x1F && u(b[off + 1]) == 0x8B) { // gzip
            return Kind.GZIP;
        }
        long m = ((long) u(b[off]) << 24) | (u(b[off + 1]) << 16) | (u(b[off + 2]) << 8) | u(b[off + 3]);
        if (m == 0xFEEDFACEL || m == 0xFEEDFACFL || m == 0xCEFAEDFEL || m == 0xCFFAEDFEL || m == 0xCAFEBABFL) {
            return Kind.MACH_O;
        }
        return Kind.NONE;
    }

    /** Finds the first offset at which a Java-class or executable signature appears, or -1. */
    public static int indexOfExecutableSignature(byte[] b, int maxScan) {
        int limit = Math.min(b.length - 4, maxScan);
        for (int i = 0; i <= limit; i++) {
            Kind k = detectAt(b, i);
            if (k == Kind.JAVA_CLASS || k == Kind.WINDOWS_PE || k == Kind.ELF_BINARY || k == Kind.MACH_O) {
                return i;
            }
        }
        return -1;
    }

    /** Shannon entropy of the bytes in bits/byte (0–8). High values suggest compression/encryption. */
    public static double entropy(byte[] b) {
        if (b == null || b.length == 0) {
            return 0;
        }
        int[] freq = new int[256];
        for (byte value : b) {
            freq[value & 0xFF]++;
        }
        double entropy = 0;
        for (int f : freq) {
            if (f == 0) {
                continue;
            }
            double p = f / (double) b.length;
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }

    private static int u(byte x) {
        return x & 0xFF;
    }
}
