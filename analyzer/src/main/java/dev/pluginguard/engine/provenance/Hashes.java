package dev.pluginguard.engine.provenance;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** Small hex-digest helper for the hashes used by the official-source APIs (sha1 / sha256 / sha512). */
public final class Hashes {

    private Hashes() {
    }

    public static String sha1(byte[] data) {
        return hex("SHA-1", data);
    }

    public static String sha256(byte[] data) {
        return hex("SHA-256", data);
    }

    public static String sha512(byte[] data) {
        return hex("SHA-512", data);
    }

    private static String hex(String algorithm, byte[] data) {
        try {
            byte[] digest = MessageDigest.getInstance(algorithm).digest(data);
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(algorithm + " not available", e);
        }
    }
}
