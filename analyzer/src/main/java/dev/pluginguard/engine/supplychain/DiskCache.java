package dev.pluginguard.engine.supplychain;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Optional;

/**
 * A tiny, dependency-free disk cache for network responses. Each entry is a file named after a
 * hash of its key; freshness is judged from the file's last-modified time against a TTL. Reads can
 * optionally ignore the TTL ({@link #getStale}) so a stale entry can still be used as a fallback
 * when the network is unavailable. All operations fail soft: a cache problem never propagates.
 */
public final class DiskCache {

    private final Path dir;
    private final Duration ttl;

    public DiskCache(Path dir, Duration ttl) {
        this.dir = dir;
        this.ttl = ttl;
    }

    /** Returns the cached value if present and newer than the TTL. */
    public Optional<String> get(String key) {
        Path file = pathFor(key);
        try {
            if (!Files.exists(file)) {
                return Optional.empty();
            }
            long ageMs = System.currentTimeMillis() - Files.getLastModifiedTime(file).toMillis();
            if (ageMs > ttl.toMillis()) {
                return Optional.empty();
            }
            return Optional.of(Files.readString(file, StandardCharsets.UTF_8));
        } catch (IOException | RuntimeException e) {
            return Optional.empty();
        }
    }

    /** Returns the cached value regardless of age (for offline/error fallback). */
    public Optional<String> getStale(String key) {
        Path file = pathFor(key);
        try {
            return Files.exists(file)
                    ? Optional.of(Files.readString(file, StandardCharsets.UTF_8))
                    : Optional.empty();
        } catch (IOException | RuntimeException e) {
            return Optional.empty();
        }
    }

    public void put(String key, String value) {
        try {
            Files.createDirectories(dir);
            Files.writeString(pathFor(key), value, StandardCharsets.UTF_8);
        } catch (IOException | RuntimeException e) {
            // best-effort cache; ignore write failures
        }
    }

    private Path pathFor(String key) {
        return dir.resolve(sha256(key) + ".json");
    }

    private static String sha256(String s) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
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
