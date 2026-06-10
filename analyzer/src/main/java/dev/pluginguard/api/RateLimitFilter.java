package dev.pluginguard.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.pluginguard.config.AnalyzerProperties;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Best-effort, in-memory rate limiter for the public, CPU-heavy upload endpoint
 * ({@code POST /api/scan}).
 *
 * <p>Cheap endpoints are deliberately <em>not</em> limited — the report page polls
 * {@code GET /api/scan/{id}} every couple of seconds while a sandbox runs, and the keep-warm job pings
 * {@code GET /api/health} — so only the upload is throttled. Requests are counted per client IP in
 * fixed one-minute windows; once the configured limit is exceeded the filter answers {@code 429} with
 * a {@code Retry-After} header, without invoking the analyzer.
 */
@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private static final long WINDOW_MS = 60_000;

    private final AnalyzerProperties.RateLimit cfg;
    private final ObjectMapper mapper;
    private final Map<String, Window> windows = new ConcurrentHashMap<>();
    private ScheduledExecutorService sweeper;

    public RateLimitFilter(AnalyzerProperties properties, ObjectMapper mapper) {
        this.cfg = properties.getRateLimit();
        this.mapper = mapper;
    }

    @PostConstruct
    void startSweeper() {
        if (!cfg.isEnabled()) {
            return;
        }
        sweeper = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "ratelimit-sweeper");
            t.setDaemon(true);
            return t;
        });
        // Drop rolled-over windows so the map doesn't accumulate idle client IPs.
        sweeper.scheduleAtFixedRate(() -> {
            long cutoff = System.currentTimeMillis() - WINDOW_MS;
            windows.values().removeIf(w -> w.start < cutoff);
        }, 1, 1, TimeUnit.MINUTES);
    }

    @PreDestroy
    void stopSweeper() {
        if (sweeper != null) {
            sweeper.shutdownNow();
        }
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        if (!cfg.isEnabled() || !isScanUpload(request)) {
            filterChain.doFilter(request, response);
            return;
        }
        long now = System.currentTimeMillis();
        Window window = windows.compute(clientIp(request), (ip, existing) -> {
            if (existing == null || now - existing.start >= WINDOW_MS) {
                return new Window(now);
            }
            existing.count++;
            return existing;
        });
        if (window.count > cfg.getScansPerMinute()) {
            long retryAfter = Math.max(1, (WINDOW_MS - (now - window.start)) / 1000);
            tooManyRequests(response, retryAfter);
            return;
        }
        filterChain.doFilter(request, response);
    }

    private static boolean isScanUpload(HttpServletRequest request) {
        return "POST".equalsIgnoreCase(request.getMethod())
                && "/api/scan".equals(request.getRequestURI());
    }

    /** Resolves the client IP, honouring X-Forwarded-For (Render terminates TLS at an upstream proxy). */
    private static String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            int comma = forwarded.indexOf(',');
            return (comma > 0 ? forwarded.substring(0, comma) : forwarded).trim();
        }
        String addr = request.getRemoteAddr();
        return addr == null ? "unknown" : addr;
    }

    private void tooManyRequests(HttpServletResponse response, long retryAfterSeconds) throws IOException {
        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setHeader(HttpHeaders.RETRY_AFTER, Long.toString(retryAfterSeconds));
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        mapper.writeValue(response.getWriter(), Map.of("error",
                "Rate limit exceeded - too many scans. Try again in " + retryAfterSeconds + " seconds."));
    }

    /** Mutable per-IP counter for the current fixed window; mutated only inside {@code compute}. */
    private static final class Window {
        final long start;
        int count;

        Window(long start) {
            this.start = start;
            this.count = 1;
        }
    }
}
