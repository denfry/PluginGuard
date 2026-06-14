package dev.pluginguard.api.auth;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** Pure unit tests for key generation/hashing — no database or Spring context. */
class ApiKeyServiceTest {

    private final ApiKeyService service = new ApiKeyService();

    @Test
    void newSecretHasLivePrefixAndIsUnique() {
        String a = service.newSecret();
        String b = service.newSecret();

        assertThat(a).startsWith(ApiKeyService.PREFIX);
        assertThat(a).isNotEqualTo(b); // SecureRandom — collisions are not expected
    }

    @Test
    void hashIsDeterministicHexAndDiffersPerKey() {
        String key = service.newSecret();

        String h1 = service.hash(key);
        String h2 = service.hash(key);

        assertThat(h1).isEqualTo(h2);
        assertThat(h1).hasSize(64).matches("[0-9a-f]+"); // SHA-256 hex
        assertThat(service.hash(service.newSecret())).isNotEqualTo(h1);
    }

    @Test
    void displayPrefixIsShortAndNonSecret() {
        String key = service.newSecret();

        String prefix = service.displayPrefix(key);

        assertThat(prefix).hasSize(16).isEqualTo(key.substring(0, 16));
        assertThat(key).startsWith(prefix);
    }
}
