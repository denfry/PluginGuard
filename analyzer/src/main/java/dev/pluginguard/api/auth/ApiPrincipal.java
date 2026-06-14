package dev.pluginguard.api.auth;

/**
 * The resolved caller of an API request. Either an authenticated organization (via API key) or an
 * anonymous client identified only by IP (the free, keyless tier).
 *
 * @param orgId     organization id, or {@code null} when anonymous
 * @param plan      organization plan, or {@code null} when anonymous
 * @param apiKeyId  id of the API key used, or {@code null} when anonymous
 * @param clientIp  best-effort client IP (used for the anonymous daily quota)
 * @param anonymous true when no valid API key was presented
 */
public record ApiPrincipal(String orgId, Plan plan, String apiKeyId, String clientIp, boolean anonymous) {

    /** Request attribute under which the interceptor stashes the resolved principal for controllers. */
    public static final String REQUEST_ATTRIBUTE = "pluginguard.principal";

    public static ApiPrincipal anonymous(String clientIp) {
        return new ApiPrincipal(null, null, null, clientIp, true);
    }

    public static ApiPrincipal keyed(String orgId, Plan plan, String apiKeyId, String clientIp) {
        return new ApiPrincipal(orgId, plan, apiKeyId, clientIp, false);
    }
}
