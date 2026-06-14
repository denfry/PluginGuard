package dev.pluginguard.api.auth;

import dev.pluginguard.config.AnalyzerProperties;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;

/**
 * Minimal provisioning API for organizations and keys (postgres profile only). Guarded by a static
 * admin token from {@code pluginguard.api.admin-token}; if that is blank the endpoints are disabled.
 * A self-service dashboard replaces this in a later slice.
 */
@RestController
@RequestMapping("/api/admin")
@Profile("postgres")
public class AdminController {

    private final ApiAccessService service;
    private final AnalyzerProperties.Api cfg;

    public AdminController(ApiAccessService service, AnalyzerProperties properties) {
        this.service = service;
        this.cfg = properties.getApi();
    }

    /** Creates an organization. Body: {@code {"name": "...", "plan": "FREE|PRO|BUSINESS"}}. */
    @PostMapping("/orgs")
    public Map<String, String> createOrg(@RequestHeader(value = "X-Admin-Token", required = false) String token,
                                         @RequestBody Map<String, String> body) {
        requireAdmin(token);
        String name = body.getOrDefault("name", "").trim();
        if (name.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "name is required.");
        }
        String id = service.createOrganization(name, body.get("plan"));
        return Map.of("id", id);
    }

    /** Issues an API key for an org. Returns the clear-text key once. Body: {@code {"name": "..."}}. */
    @PostMapping("/orgs/{orgId}/keys")
    public Map<String, String> createKey(@RequestHeader(value = "X-Admin-Token", required = false) String token,
                                         @PathVariable String orgId,
                                         @RequestBody(required = false) Map<String, String> body) {
        requireAdmin(token);
        String name = body == null ? null : body.get("name");
        return service.createKey(orgId, name);
    }

    private void requireAdmin(String token) {
        String configured = cfg.getAdminToken();
        if (configured == null || configured.isBlank()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Admin API is disabled.");
        }
        if (!configured.equals(token)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid admin token.");
        }
    }
}
