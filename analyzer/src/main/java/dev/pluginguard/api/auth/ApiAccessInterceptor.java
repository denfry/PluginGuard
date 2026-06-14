package dev.pluginguard.api.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * Authenticates the API key, enforces the quota before the scan runs, and meters the call after a
 * successful response. Registered on {@code POST /api/scan} only, under the {@code postgres} profile
 * (see {@link ApiWebConfig}). The default in-memory profile has no interceptor — every call is the
 * keyless free tier with no limits, exactly as before.
 */
@Component
@Profile("postgres")
public class ApiAccessInterceptor implements HandlerInterceptor {

    private static final String PRINCIPAL_ATTR = ApiPrincipal.REQUEST_ATTRIBUTE;

    private final ApiAccessService service;

    public ApiAccessInterceptor(ApiAccessService service) {
        this.service = service;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        ApiPrincipal principal = service.resolve(request.getHeader("Authorization"), clientIp(request));
        service.enforceQuota(principal); // throws 401/429 → handled by Spring as the HTTP response
        request.setAttribute(PRINCIPAL_ATTR, principal);
        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response,
                                Object handler, Exception ex) {
        Object attr = request.getAttribute(PRINCIPAL_ATTR);
        int status = response.getStatus();
        if (attr instanceof ApiPrincipal principal && status >= 200 && status < 300) {
            service.record(principal, request.getRequestURI(), status);
        }
    }

    /** Best-effort client IP, honoring a single-hop {@code X-Forwarded-For} from a trusted proxy. */
    private static String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            int comma = forwarded.indexOf(',');
            return (comma > 0 ? forwarded.substring(0, comma) : forwarded).trim();
        }
        return request.getRemoteAddr();
    }
}
