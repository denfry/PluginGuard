package dev.pluginguard.api.auth;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Generation and hashing of API keys. Pure (no database) so it is unit-testable without any
 * infrastructure. Keys look like {@code pg_live_<random>}; only their SHA-256 hash and a short
 * display prefix are ever persisted.
 */
@Component
public class ApiKeyService {

    public static final String PREFIX = "pg_live_";
    private static final int SECRET_BYTES = 24;     // 32 url-safe base64 chars
    private static final int DISPLAY_PREFIX_LEN = 16;

    private final SecureRandom random = new SecureRandom();

    /** Mints a new clear-text key. Shown to the caller once; never stored as-is. */
    public String newSecret() {
        byte[] buf = new byte[SECRET_BYTES];
        random.nextBytes(buf);
        return PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }

    /** SHA-256 hex of a key — the value stored and looked up. */
    public String hash(String key) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(key.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e); // never on a standard JRE
        }
    }

    /** Short, non-secret prefix kept for display (e.g. in a dashboard key list). */
    public String displayPrefix(String key) {
        return key.substring(0, Math.min(key.length(), DISPLAY_PREFIX_LEN));
    }
}
