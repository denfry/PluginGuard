package dev.pluginguard.api.auth;

import dev.pluginguard.support.AbstractPostgresIT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Integration tests for {@link ApiAccessService} against a real PostgreSQL: provisioning, key
 * resolution, and quota enforcement (per-plan monthly + anonymous per-IP daily).
 */
@TestPropertySource(properties = "pluginguard.api.anonymous-daily-limit=3")
class ApiAccessServiceIT extends AbstractPostgresIT {

    @Autowired
    private ApiAccessService service;
    @Autowired
    private JdbcTemplate jdbc;

    @BeforeEach
    void clean() {
        jdbc.execute("TRUNCATE organization, api_key, usage_event RESTART IDENTITY CASCADE");
    }

    @Test
    void provisionsAndResolvesAKey() {
        String orgId = service.createOrganization("Acme", "PRO");
        Map<String, String> key = service.createKey(orgId, "ci");

        ApiPrincipal principal = service.resolve("Bearer " + key.get("key"), "1.2.3.4");

        assertThat(principal.anonymous()).isFalse();
        assertThat(principal.orgId()).isEqualTo(orgId);
        assertThat(principal.plan()).isEqualTo(Plan.PRO);
    }

    @Test
    void noHeaderResolvesAsAnonymous() {
        assertThat(service.resolve(null, "1.2.3.4").anonymous()).isTrue();
    }

    @Test
    void invalidKeyIsRejected() {
        assertThatThrownBy(() -> service.resolve("Bearer pg_live_bogus", "1.2.3.4"))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode().value()).isEqualTo(401));
    }

    @Test
    void enforcesMonthlyPlanQuota() {
        String orgId = service.createOrganization("Acme", "FREE"); // monthly limit 100
        ApiPrincipal principal = ApiPrincipal.keyed(orgId, Plan.FREE, "key-1", "1.2.3.4");
        int limit = Plan.FREE.monthlyScanLimit();

        seedOrgUsage(orgId, limit - 1);
        service.enforceQuota(principal); // under the limit → no throw

        seedOrgUsage(orgId, 1); // now at the limit
        assertThatThrownBy(() -> service.enforceQuota(principal))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode().value()).isEqualTo(429));
    }

    @Test
    void enforcesAnonymousDailyQuota() {
        ApiPrincipal anon = ApiPrincipal.anonymous("9.9.9.9"); // limit 3 (see @TestPropertySource)

        seedAnonUsage("9.9.9.9", 2);
        service.enforceQuota(anon); // 2 < 3 → no throw

        seedAnonUsage("9.9.9.9", 1); // now 3
        assertThatThrownBy(() -> service.enforceQuota(anon))
                .isInstanceOf(ResponseStatusException.class)
                .satisfies(e -> assertThat(((ResponseStatusException) e).getStatusCode().value()).isEqualTo(429));
    }

    @Test
    void recordPersistsAUsageRow() {
        String orgId = service.createOrganization("Acme", "PRO");
        ApiPrincipal principal = ApiPrincipal.keyed(orgId, Plan.PRO, "key-1", "1.2.3.4");

        service.record(principal, "/api/scan", 200);

        Integer rows = jdbc.queryForObject(
                "SELECT count(*) FROM usage_event WHERE org_id = ?", Integer.class, orgId);
        assertThat(rows).isEqualTo(1);
    }

    private void seedOrgUsage(String orgId, int n) {
        jdbc.update("INSERT INTO usage_event (org_id, endpoint, status) "
                + "SELECT ?, '/api/scan', 200 FROM generate_series(1, ?)", orgId, n);
    }

    private void seedAnonUsage(String ip, int n) {
        jdbc.update("INSERT INTO usage_event (ip, endpoint, status) "
                + "SELECT ?, '/api/scan', 200 FROM generate_series(1, ?)", ip, n);
    }
}
