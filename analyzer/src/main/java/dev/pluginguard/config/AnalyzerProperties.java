package dev.pluginguard.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Externalized configuration bound from the {@code pluginguard.*} keys in {@code application.yml}.
 */
@ConfigurationProperties(prefix = "pluginguard")
public class AnalyzerProperties {

    private Cors cors = new Cors();
    private Limits limits = new Limits();

    public Cors getCors() { return cors; }
    public void setCors(Cors cors) { this.cors = cors; }
    public Limits getLimits() { return limits; }
    public void setLimits(Limits limits) { this.limits = limits; }

    public static class Cors {
        /** Comma-separated list of origins allowed to call the API. */
        private String allowedOrigins = "http://localhost:3000";

        public String getAllowedOrigins() { return allowedOrigins; }
        public void setAllowedOrigins(String allowedOrigins) { this.allowedOrigins = allowedOrigins; }

        public String[] origins() {
            return allowedOrigins.split("\\s*,\\s*");
        }
    }

    /** Zip-bomb / resource guards applied while unpacking an uploaded JAR. */
    public static class Limits {
        private long maxTotalUncompressedBytes = 524_288_000L; // 500 MB
        private long maxEntryUncompressedBytes = 67_108_864L;  // 64 MB
        private int maxEntries = 50_000;
        private int maxCompressionRatio = 200;
        private int maxNestedJarDepth = 2;

        public long getMaxTotalUncompressedBytes() { return maxTotalUncompressedBytes; }
        public void setMaxTotalUncompressedBytes(long v) { this.maxTotalUncompressedBytes = v; }
        public long getMaxEntryUncompressedBytes() { return maxEntryUncompressedBytes; }
        public void setMaxEntryUncompressedBytes(long v) { this.maxEntryUncompressedBytes = v; }
        public int getMaxEntries() { return maxEntries; }
        public void setMaxEntries(int v) { this.maxEntries = v; }
        public int getMaxCompressionRatio() { return maxCompressionRatio; }
        public void setMaxCompressionRatio(int v) { this.maxCompressionRatio = v; }
        public int getMaxNestedJarDepth() { return maxNestedJarDepth; }
        public void setMaxNestedJarDepth(int v) { this.maxNestedJarDepth = v; }
    }
}
