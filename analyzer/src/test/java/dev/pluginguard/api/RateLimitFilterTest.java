package dev.pluginguard.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.pluginguard.config.AnalyzerProperties;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;

/** Unit tests for the per-IP upload rate limiter (no Spring context needed). */
class RateLimitFilterTest {

    private static AnalyzerProperties props(int scansPerMinute) {
        AnalyzerProperties p = new AnalyzerProperties();
        p.getRateLimit().setEnabled(true);
        p.getRateLimit().setScansPerMinute(scansPerMinute);
        return p;
    }

    private static int scan(RateLimitFilter filter, String ip) throws Exception {
        return request(filter, "POST", "/api/scan", ip);
    }

    private static int request(RateLimitFilter filter, String method, String uri, String ip)
            throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest(method, uri);
        req.setRemoteAddr(ip);
        MockHttpServletResponse res = new MockHttpServletResponse();
        filter.doFilter(req, res, new MockFilterChain());
        return res.getStatus();
    }

    @Test
    void allowsUpToLimitThenReturns429() throws Exception {
        RateLimitFilter filter = new RateLimitFilter(props(3), new ObjectMapper());
        assertThat(scan(filter, "1.1.1.1")).isEqualTo(200);
        assertThat(scan(filter, "1.1.1.1")).isEqualTo(200);
        assertThat(scan(filter, "1.1.1.1")).isEqualTo(200);
        assertThat(scan(filter, "1.1.1.1")).isEqualTo(429); // 4th in the window is blocked
    }

    @Test
    void limitIsPerClientIp() throws Exception {
        RateLimitFilter filter = new RateLimitFilter(props(1), new ObjectMapper());
        assertThat(scan(filter, "1.1.1.1")).isEqualTo(200);
        assertThat(scan(filter, "1.1.1.1")).isEqualTo(429);
        assertThat(scan(filter, "2.2.2.2")).isEqualTo(200); // a different IP is unaffected
    }

    @Test
    void readsAreNeverLimited() throws Exception {
        RateLimitFilter filter = new RateLimitFilter(props(1), new ObjectMapper());
        // Report polling / health must not be throttled, even well past the upload limit.
        for (int i = 0; i < 5; i++) {
            assertThat(request(filter, "GET", "/api/scan/some-id", "9.9.9.9")).isEqualTo(200);
        }
        assertThat(request(filter, "GET", "/api/health", "9.9.9.9")).isEqualTo(200);
    }

    @Test
    void honoursXForwardedForBehindAProxy() throws Exception {
        RateLimitFilter filter = new RateLimitFilter(props(1), new ObjectMapper());
        // Same proxy remoteAddr, different real clients via X-Forwarded-For → counted separately.
        MockHttpServletRequest a = new MockHttpServletRequest("POST", "/api/scan");
        a.setRemoteAddr("10.0.0.1");
        a.addHeader("X-Forwarded-For", "203.0.113.1, 10.0.0.1");
        MockHttpServletResponse ra = new MockHttpServletResponse();
        filter.doFilter(a, ra, new MockFilterChain());
        assertThat(ra.getStatus()).isEqualTo(200);

        MockHttpServletRequest b = new MockHttpServletRequest("POST", "/api/scan");
        b.setRemoteAddr("10.0.0.1");
        b.addHeader("X-Forwarded-For", "203.0.113.2, 10.0.0.1");
        MockHttpServletResponse rb = new MockHttpServletResponse();
        filter.doFilter(b, rb, new MockFilterChain());
        assertThat(rb.getStatus()).isEqualTo(200); // different forwarded client, own budget
    }

    @Test
    void disabledLimiterNeverBlocks() throws Exception {
        AnalyzerProperties p = new AnalyzerProperties();
        p.getRateLimit().setEnabled(false);
        RateLimitFilter filter = new RateLimitFilter(p, new ObjectMapper());
        for (int i = 0; i < 50; i++) {
            assertThat(scan(filter, "1.1.1.1")).isEqualTo(200);
        }
    }
}
