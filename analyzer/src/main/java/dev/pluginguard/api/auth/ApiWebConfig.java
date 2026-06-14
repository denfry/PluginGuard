package dev.pluginguard.api.auth;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Registers {@link ApiAccessInterceptor} on the scan endpoint (postgres profile only). Coexists with
 * the CORS {@code WebMvcConfigurer} — Spring applies all of them.
 */
@Configuration
@Profile("postgres")
public class ApiWebConfig implements WebMvcConfigurer {

    private final ApiAccessInterceptor interceptor;

    public ApiWebConfig(ApiAccessInterceptor interceptor) {
        this.interceptor = interceptor;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        // Auth/quota/metering apply to submitting a scan (single or batch). Report retrieval and
        // demo/health stay open.
        registry.addInterceptor(interceptor).addPathPatterns("/api/scan", "/api/scan/batch");
    }
}
