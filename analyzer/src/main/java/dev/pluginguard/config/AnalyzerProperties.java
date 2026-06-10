package dev.pluginguard.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.nio.file.Path;

/**
 * Externalized configuration bound from the {@code pluginguard.*} keys in {@code application.yml}.
 */
@ConfigurationProperties(prefix = "pluginguard")
public class AnalyzerProperties {

    private Cors cors = new Cors();
    private Limits limits = new Limits();
    private SupplyChain supplyChain = new SupplyChain();
    private Sandbox sandbox = new Sandbox();
    private RateLimit rateLimit = new RateLimit();

    public Cors getCors() { return cors; }
    public void setCors(Cors cors) { this.cors = cors; }
    public Limits getLimits() { return limits; }
    public void setLimits(Limits limits) { this.limits = limits; }
    public SupplyChain getSupplyChain() { return supplyChain; }
    public void setSupplyChain(SupplyChain supplyChain) { this.supplyChain = supplyChain; }
    public Sandbox getSandbox() { return sandbox; }
    public void setSandbox(Sandbox sandbox) { this.sandbox = sandbox; }
    public RateLimit getRateLimit() { return rateLimit; }
    public void setRateLimit(RateLimit rateLimit) { this.rateLimit = rateLimit; }

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

    /**
     * Phase&nbsp;2 supply-chain &amp; reputation. Both features are <strong>off by default</strong>:
     * they reach the network, so they only run when explicitly enabled. {@code offline} is a hard
     * kill-switch that disables all outbound requests regardless of the per-feature flags (cached
     * results are still used).
     */
    public static class SupplyChain {
        private boolean cveEnabled = false;
        private boolean reputationEnabled = false;
        private boolean offline = false;

        /** OSV.dev single-query endpoint (returns full vulnerability details). */
        private String osvApiUrl = "https://api.osv.dev/v1/query";
        /** Disk cache directory; empty → {@code <java.io.tmpdir>/pluginguard-cache}. */
        private String cacheDir = "";
        private long cacheTtlHours = 168; // 7 days
        private int timeoutMs = 4000;
        private int retries = 1;

        /** Source of known-malicious SHA-256 hashes: a local file path or an http(s) URL. */
        private String knownMaliciousSource = "";
        /** Source of known-good SHA-256 hashes: a local file path or an http(s) URL. */
        private String knownGoodSource = "";

        public boolean isCveEnabled() { return cveEnabled; }
        public void setCveEnabled(boolean v) { this.cveEnabled = v; }
        public boolean isReputationEnabled() { return reputationEnabled; }
        public void setReputationEnabled(boolean v) { this.reputationEnabled = v; }
        public boolean isOffline() { return offline; }
        public void setOffline(boolean v) { this.offline = v; }
        public String getOsvApiUrl() { return osvApiUrl; }
        public void setOsvApiUrl(String v) { this.osvApiUrl = v; }
        public String getCacheDir() { return cacheDir; }
        public void setCacheDir(String v) { this.cacheDir = v; }
        public long getCacheTtlHours() { return cacheTtlHours; }
        public void setCacheTtlHours(long v) { this.cacheTtlHours = v; }
        public int getTimeoutMs() { return timeoutMs; }
        public void setTimeoutMs(int v) { this.timeoutMs = v; }
        public int getRetries() { return retries; }
        public void setRetries(int v) { this.retries = v; }
        public String getKnownMaliciousSource() { return knownMaliciousSource; }
        public void setKnownMaliciousSource(String v) { this.knownMaliciousSource = v; }
        public String getKnownGoodSource() { return knownGoodSource; }
        public void setKnownGoodSource(String v) { this.knownGoodSource = v; }

        /** Resolves the effective cache directory, defaulting under the system temp dir. */
        public Path resolveCacheDir() {
            if (cacheDir != null && !cacheDir.isBlank()) {
                return Path.of(cacheDir);
            }
            return Path.of(System.getProperty("java.io.tmpdir", "."), "pluginguard-cache");
        }
    }

    /**
     * Phase&nbsp;3 dynamic sandbox. <strong>Off by default</strong>: it actually executes the
     * uploaded plugin, so it only runs when explicitly enabled <em>and</em> a hardened container
     * runtime (Docker) is present. The static analyzer never executes the jar regardless of this.
     */
    public static class Sandbox {
        private boolean enabled = false;
        /** Runtime that isolates execution. Only {@code docker} is implemented. */
        private String runner = "docker";
        private String dockerPath = "docker";
        /** Base JRE image the sandbox container runs. */
        private String image = "eclipse-temurin:21-jre";
        /** Path on the analyzer host to the built {@code sandbox-runtime} agent jar. */
        private String runtimeJarPath = "";
        /** Host directory for per-run work mounts; empty → {@code <java.io.tmpdir>/pluginguard-sandbox}. */
        private String workDir = "";
        /** Hard wall-clock limit for one sandbox run. */
        private int timeoutSeconds = 20;
        private int memoryMb = 256;
        private String cpus = "1.0";
        private int pidsLimit = 128;
        /** Container network mode; {@code none} fully isolates, blocking and logging all egress. */
        private String network = "none";
        /** Cap on raw behavior events embedded in the report. */
        private int maxBehaviorEvents = 500;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean v) { this.enabled = v; }
        public String getRunner() { return runner; }
        public void setRunner(String v) { this.runner = v; }
        public String getDockerPath() { return dockerPath; }
        public void setDockerPath(String v) { this.dockerPath = v; }
        public String getImage() { return image; }
        public void setImage(String v) { this.image = v; }
        public String getRuntimeJarPath() { return runtimeJarPath; }
        public void setRuntimeJarPath(String v) { this.runtimeJarPath = v; }
        public String getWorkDir() { return workDir; }
        public void setWorkDir(String v) { this.workDir = v; }
        public int getTimeoutSeconds() { return timeoutSeconds; }
        public void setTimeoutSeconds(int v) { this.timeoutSeconds = v; }
        public int getMemoryMb() { return memoryMb; }
        public void setMemoryMb(int v) { this.memoryMb = v; }
        public String getCpus() { return cpus; }
        public void setCpus(String v) { this.cpus = v; }
        public int getPidsLimit() { return pidsLimit; }
        public void setPidsLimit(int v) { this.pidsLimit = v; }
        public String getNetwork() { return network; }
        public void setNetwork(String v) { this.network = v; }
        public int getMaxBehaviorEvents() { return maxBehaviorEvents; }
        public void setMaxBehaviorEvents(int v) { this.maxBehaviorEvents = v; }

        /** Resolves the effective work directory, defaulting under the system temp dir. */
        public Path resolveWorkDir() {
            if (workDir != null && !workDir.isBlank()) {
                return Path.of(workDir);
            }
            return Path.of(System.getProperty("java.io.tmpdir", "."), "pluginguard-sandbox");
        }
    }

    /**
     * Best-effort per-client rate limiting for the public, CPU-heavy upload endpoint
     * ({@code POST /api/scan}). Cheap reads (report polling, demo, health) are never limited.
     * In-memory, per-IP, fixed one-minute windows — sized for a single free-tier instance.
     */
    public static class RateLimit {
        private boolean enabled = true;
        /** Max {@code POST /api/scan} requests allowed per client IP per minute. */
        private int scansPerMinute = 10;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public int getScansPerMinute() { return scansPerMinute; }
        public void setScansPerMinute(int scansPerMinute) { this.scansPerMinute = scansPerMinute; }
    }
}
