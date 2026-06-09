package dev.pluginguard.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Enables CORS for the configured web-app origins so the Next.js frontend can call the analyzer API.
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {

    private final AnalyzerProperties properties;

    public WebConfig(AnalyzerProperties properties) {
        this.properties = properties;
    }

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
                .allowedOrigins(properties.getCors().origins())
                .allowedMethods("GET", "POST", "OPTIONS")
                .allowedHeaders("*")
                .maxAge(3600);
    }
}
