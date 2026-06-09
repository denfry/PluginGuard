package dev.pluginguard.engine.util;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Best-effort decoder for obfuscated payloads embedded as string constants: standard/URL base64,
 * hex, and single-byte XOR over either. It never executes anything — it just transforms bytes so
 * a downstream analyzer can look for embedded classes, archives or IOCs in the decoded result.
 *
 * <p>All operations are bounded (decoded size, XOR key search) so a hostile input cannot turn
 * decoding into a denial-of-service.
 */
public final class PayloadDecoder {

    /** Minimum length of a string we bother trying to decode. */
    public static final int MIN_CANDIDATE_LENGTH = 32;

    private static final Base64.Decoder STD = Base64.getDecoder();
    private static final Base64.Decoder URL = Base64.getUrlDecoder();

    private PayloadDecoder() {
    }

    /** One decoding result with a human-readable description of how it was obtained. */
    public record Decoded(byte[] bytes, String method) {
    }

    /**
     * Decodes {@code s} every plausible way and returns the results worth inspecting. {@code maxBytes}
     * caps each decoded blob; {@code tryXor} enables the (more expensive) single-byte XOR search.
     */
    public static List<Decoded> decode(String s, int maxBytes, boolean tryXor) {
        List<Decoded> out = new ArrayList<>();
        if (s == null || s.length() < MIN_CANDIDATE_LENGTH) {
            return out;
        }
        String trimmed = s.trim();

        byte[] b64 = tryBase64(trimmed, maxBytes);
        if (b64 != null) {
            out.add(new Decoded(b64, "base64"));
            if (tryXor) {
                addXorReveals(out, b64, "base64+xor");
            }
        }

        byte[] hex = tryHex(trimmed, maxBytes);
        if (hex != null) {
            out.add(new Decoded(hex, "hex"));
            if (tryXor) {
                addXorReveals(out, hex, "hex+xor");
            }
        }

        return out;
    }

    private static byte[] tryBase64(String s, int maxBytes) {
        if (!looksBase64(s)) {
            return null;
        }
        try {
            byte[] decoded = STD.decode(stripBase64(s));
            return cap(decoded, maxBytes);
        } catch (IllegalArgumentException e) {
            try {
                byte[] decoded = URL.decode(stripBase64(s));
                return cap(decoded, maxBytes);
            } catch (IllegalArgumentException ignored) {
                return null;
            }
        }
    }

    private static byte[] tryHex(String s, int maxBytes) {
        String hex = s.startsWith("0x") || s.startsWith("0X") ? s.substring(2) : s;
        if (hex.length() < MIN_CANDIDATE_LENGTH || hex.length() % 2 != 0) {
            return null;
        }
        for (int i = 0; i < hex.length(); i++) {
            char c = hex.charAt(i);
            boolean isHex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!isHex) {
                return null;
            }
        }
        int n = Math.min(hex.length() / 2, maxBytes);
        byte[] out = new byte[n];
        for (int i = 0; i < n; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    /** Searches single-byte XOR keys; keeps a result only if it reveals an executable/archive signature. */
    private static void addXorReveals(List<Decoded> out, byte[] data, String label) {
        if (data.length < 4) {
            return;
        }
        for (int key = 1; key < 256; key++) {
            int b0 = (data[0] ^ key) & 0xFF;
            // Cheap pre-check on the first byte before XOR-ing the whole buffer.
            if (b0 != 0xCA && b0 != 0x50 && b0 != 0x4D && b0 != 0x7F) {
                continue;
            }
            byte[] x = new byte[data.length];
            for (int i = 0; i < data.length; i++) {
                x[i] = (byte) (data[i] ^ key);
            }
            if (Magic.detect(x) != Magic.Kind.NONE) {
                out.add(new Decoded(x, label + ":0x" + Integer.toHexString(key)));
            }
        }
    }

    private static boolean looksBase64(String s) {
        String t = stripBase64(s);
        if (t.length() < MIN_CANDIDATE_LENGTH) {
            return false;
        }
        for (int i = 0; i < t.length(); i++) {
            char c = t.charAt(i);
            boolean ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '+' || c == '/' || c == '-' || c == '_' || c == '=';
            if (!ok) {
                return false;
            }
        }
        return true;
    }

    private static String stripBase64(String s) {
        return s.replaceAll("\\s", "");
    }

    private static byte[] cap(byte[] b, int maxBytes) {
        if (b.length <= maxBytes) {
            return b;
        }
        byte[] out = new byte[maxBytes];
        System.arraycopy(b, 0, out, 0, maxBytes);
        return out;
    }
}
