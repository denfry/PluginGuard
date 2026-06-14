package dev.pluginguard.api.auth;

import dev.pluginguard.config.AnalyzerProperties;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Database-backed core of the B2B API platform: resolve an API key to a principal, enforce per-plan
 * (or anonymous per-IP) quotas, meter usage, and provision organizations/keys. Active only under the
 * {@code postgres} profile.
 *
 * <p>Quota is enforced by counting {@code usage_event} rows in the current period and recording one
 * row per successful scan. Under heavy concurrency a small over-count past the limit is possible;
 * acceptable for this slice and tightened later (reservations / Redis) if needed.
 */
@Service
@Profile("postgres")
public class ApiAccessService {

    private static final String BEARER = "Bearer ";

    private final JdbcTemplate jdbc;
    private final ApiKeyService keys;
    private final AnalyzerProperties.Api cfg;

    public ApiAccessService(JdbcTemplate jdbc, ApiKeyService keys, AnalyzerProperties properties) {
        this.jdbc = jdbc;
        this.keys = keys;
        this.cfg = properties.getApi();
    }

    /**
     * Resolves the caller. No {@code Authorization} header → anonymous (free tier). A valid key →
     * the owning organization. A present-but-invalid/revoked key → 401.
     */
    public ApiPrincipal resolve(String authHeader, String clientIp) {
        String token = bearer(authHeader);
        if (token == null) {
            return ApiPrincipal.anonymous(clientIp);
        }
        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT k.id AS key_id, k.org_id AS org_id, o.plan AS plan "
                        + "FROM api_key k JOIN organization o ON o.id = k.org_id "
                        + "WHERE k.key_hash = ? AND k.revoked = false",
                keys.hash(token));
        if (rows.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid or revoked API key.");
        }
        Map<String, Object> row = rows.get(0);
        String keyId = (String) row.get("key_id");
        jdbc.update("UPDATE api_key SET last_used_at = now() WHERE id = ?", keyId);
        return ApiPrincipal.keyed((String) row.get("org_id"), Plan.fromString((String) row.get("plan")),
                keyId, clientIp);
    }

    /** Throws 429 when the caller is over its quota (per-plan monthly, or anonymous per-IP daily). */
    public void enforceQuota(ApiPrincipal principal) {
        if (principal.anonymous()) {
            int limit = cfg.getAnonymousDailyLimit();
            if (limit <= 0) {
                return; // disabled
            }
            Integer used = jdbc.queryForObject(
                    "SELECT count(*) FROM usage_event "
                            + "WHERE org_id IS NULL AND ip = ? AND created_at >= date_trunc('day', now())",
                    Integer.class, principal.clientIp());
            if (used != null && used >= limit) {
                throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,
                        "Free daily scan limit reached (" + limit + "/day). Use an API key for a higher quota.");
            }
        } else {
            int limit = principal.plan().monthlyScanLimit();
            Integer used = jdbc.queryForObject(
                    "SELECT count(*) FROM usage_event "
                            + "WHERE org_id = ? AND created_at >= date_trunc('month', now())",
                    Integer.class, principal.orgId());
            if (used != null && used >= limit) {
                throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS,
                        "Monthly scan quota reached (" + limit + ") for the " + principal.plan() + " plan.");
            }
        }
    }

    /** Records one metered call. Called after a successful scan. */
    public void record(ApiPrincipal principal, String endpoint, int status) {
        jdbc.update("INSERT INTO usage_event (org_id, api_key_id, ip, endpoint, status) VALUES (?, ?, ?, ?, ?)",
                principal.orgId(), principal.apiKeyId(), principal.clientIp(), endpoint, status);
    }

    // ---- provisioning (admin) --------------------------------------------------------------------

    public String createOrganization(String name, String plan) {
        String id = UUID.randomUUID().toString();
        jdbc.update("INSERT INTO organization (id, name, plan) VALUES (?, ?, ?)",
                id, name, Plan.fromString(plan).name());
        return id;
    }

    /** Creates a key for an org and returns the clear-text secret (shown once). */
    public Map<String, String> createKey(String orgId, String name) {
        Integer exists = jdbc.queryForObject("SELECT count(*) FROM organization WHERE id = ?", Integer.class, orgId);
        if (exists == null || exists == 0) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Organization not found.");
        }
        String secret = keys.newSecret();
        String id = UUID.randomUUID().toString();
        jdbc.update("INSERT INTO api_key (id, org_id, key_hash, key_prefix, name) VALUES (?, ?, ?, ?, ?)",
                id, orgId, keys.hash(secret), keys.displayPrefix(secret), name);
        return Map.of("id", id, "key", secret, "prefix", keys.displayPrefix(secret));
    }

    private static String bearer(String authHeader) {
        if (authHeader == null || !authHeader.startsWith(BEARER)) {
            return null;
        }
        String token = authHeader.substring(BEARER.length()).trim();
        return token.isEmpty() ? null : token;
    }
}
