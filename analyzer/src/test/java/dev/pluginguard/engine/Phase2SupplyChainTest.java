package dev.pluginguard.engine;

import com.sun.net.httpserver.HttpServer;
import dev.pluginguard.config.AnalyzerProperties;
import dev.pluginguard.engine.analyzers.CveAnalyzer;
import dev.pluginguard.engine.analyzers.DependencyAnalyzer;
import dev.pluginguard.engine.analyzers.ReputationAnalyzer;
import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.JarModel;
import dev.pluginguard.engine.model.Severity;
import dev.pluginguard.engine.supplychain.OsvClient;
import dev.pluginguard.engine.supplychain.ReputationService;
import dev.pluginguard.support.JarBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Phase&nbsp;2 supply-chain tests. These run the network-facing components directly (no Spring)
 * against a local {@link HttpServer} serving canned OSV responses and temp-file reputation lists,
 * so they exercise the real HTTP / cache / parse paths deterministically and offline-safe.
 */
class Phase2SupplyChainTest {

    private static final String OSV_RESPONSE = """
            {"vulns":[
              {"id":"GHSA-test-0001","summary":"Test vulnerability in vuln-lib",
               "database_specific":{"severity":"HIGH"},
               "severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
            ]}""";

    private static AnalyzerProperties props(Path cacheDir) {
        AnalyzerProperties p = new AnalyzerProperties();
        p.getSupplyChain().setCacheDir(cacheDir.toString());
        p.getSupplyChain().setRetries(0);
        p.getSupplyChain().setTimeoutMs(2000);
        return p;
    }

    private static byte[] vulnerablePluginJar() {
        return new JarBuilder()
                .addClass("com/example/app/AppPlugin")
                .addResource("plugin.yml",
                        "name: App\nversion: \"1.0\"\nmain: com.example.app.AppPlugin\napi-version: \"1.21\"\n")
                .addResource("META-INF/maven/com.example/vuln-lib/pom.properties",
                        "groupId=com.example\nartifactId=vuln-lib\nversion=1.0.0\n")
                .build();
    }

    private static AnalysisContext contextFor(AnalyzerProperties p, byte[] jarBytes) {
        JarModel jar = new JarLoader(p).load("app.jar", jarBytes);
        AnalysisContext ctx = new AnalysisContext(jar, List.<ClassScan>of());
        new DependencyAnalyzer().analyze(ctx); // populate ctx.dependencies()
        return ctx;
    }

    private static HttpServer startServer(String body, AtomicInteger hits) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/query", exchange -> {
            hits.incrementAndGet();
            exchange.getRequestBody().readAllBytes();
            byte[] out = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, out.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(out);
            }
        });
        server.start();
        return server;
    }

    @Test
    void cveLookupFlagsVulnerableDependency(@TempDir Path cacheDir) throws IOException {
        AtomicInteger hits = new AtomicInteger();
        HttpServer server = startServer(OSV_RESPONSE, hits);
        try {
            AnalyzerProperties p = props(cacheDir);
            p.getSupplyChain().setCveEnabled(true);
            p.getSupplyChain().setOsvApiUrl("http://127.0.0.1:" + server.getAddress().getPort() + "/v1/query");

            AnalysisContext ctx = contextFor(p, vulnerablePluginJar());
            new CveAnalyzer(p, new OsvClient(p)).analyze(ctx);

            Finding cve = ctx.findings().stream()
                    .filter(f -> f.ruleId().equals("CVE_GHSA-test-0001"))
                    .findFirst().orElse(null);
            assertThat(cve).isNotNull();
            assertThat(cve.severity()).isEqualTo(Severity.HIGH);
            assertThat(cve.location()).contains("com.example:vuln-lib");
            assertThat(cve.recommendation()).contains("osv.dev/vulnerability/GHSA-test-0001");
            assertThat(hits.get()).isEqualTo(1);
        } finally {
            server.stop(0);
        }
    }

    @Test
    void cveResultIsServedFromCacheWithoutNetwork(@TempDir Path cacheDir) throws IOException {
        AtomicInteger hits = new AtomicInteger();
        HttpServer server = startServer(OSV_RESPONSE, hits);
        AnalyzerProperties p = props(cacheDir);
        p.getSupplyChain().setCveEnabled(true);
        p.getSupplyChain().setOsvApiUrl("http://127.0.0.1:" + server.getAddress().getPort() + "/v1/query");
        try {
            // Warm the cache.
            new CveAnalyzer(p, new OsvClient(p)).analyze(contextFor(p, vulnerablePluginJar()));
            assertThat(hits.get()).isEqualTo(1);
        } finally {
            server.stop(0);
        }

        // Server is down and we go offline — the fresh cache entry must still answer.
        p.getSupplyChain().setOffline(true);
        AnalysisContext ctx = contextFor(p, vulnerablePluginJar());
        new CveAnalyzer(p, new OsvClient(p)).analyze(ctx);

        assertThat(ctx.findings().stream().anyMatch(f -> f.ruleId().equals("CVE_GHSA-test-0001"))).isTrue();
        assertThat(hits.get()).isEqualTo(1); // no second network call
    }

    @Test
    void cveLookupDegradesGracefullyWhenUnavailable(@TempDir Path cacheDir) {
        AnalyzerProperties p = props(cacheDir);
        p.getSupplyChain().setCveEnabled(true);
        p.getSupplyChain().setOffline(true); // no network, empty cache → unavailable

        AnalysisContext ctx = contextFor(p, vulnerablePluginJar());
        new CveAnalyzer(p, new OsvClient(p)).analyze(ctx);

        assertThat(ctx.findings().stream().noneMatch(f -> f.ruleId().startsWith("CVE_"))).isTrue();
        assertThat(ctx.notes()).anyMatch(n -> n.contains("CVE lookup was unavailable"));
    }

    @Test
    void disabledCveAnalyzerDoesNothing(@TempDir Path cacheDir) {
        AnalyzerProperties p = props(cacheDir); // cve-enabled stays false
        AnalysisContext ctx = contextFor(p, vulnerablePluginJar());
        new CveAnalyzer(p, new OsvClient(p)).analyze(ctx);

        assertThat(ctx.findings().stream().noneMatch(f -> f.ruleId().startsWith("CVE_"))).isTrue();
        assertThat(ctx.notes()).noneMatch(n -> n.contains("CVE lookup was unavailable"));
    }

    @Test
    void knownMaliciousHashIsCritical(@TempDir Path cacheDir) throws IOException {
        AnalyzerProperties p = props(cacheDir);
        byte[] jarBytes = vulnerablePluginJar();
        JarModel jar = new JarLoader(p).load("app.jar", jarBytes);

        Path list = cacheDir.resolve("malicious.txt");
        Files.writeString(list, "# bad hashes\n" + jar.sha256() + "  app.jar\n");
        p.getSupplyChain().setReputationEnabled(true);
        p.getSupplyChain().setKnownMaliciousSource(list.toString());

        AnalysisContext ctx = new AnalysisContext(jar, List.<ClassScan>of());
        new ReputationAnalyzer(p, new ReputationService(p)).analyze(ctx);

        Finding hit = ctx.findings().stream()
                .filter(f -> f.ruleId().equals("REPUTATION_KNOWN_MALICIOUS"))
                .findFirst().orElse(null);
        assertThat(hit).isNotNull();
        assertThat(hit.severity()).isEqualTo(Severity.CRITICAL);
        assertThat(hit.evidence()).isEqualTo(jar.sha256());
    }

    @Test
    void knownGoodHashIsInformational(@TempDir Path cacheDir) throws IOException {
        AnalyzerProperties p = props(cacheDir);
        byte[] jarBytes = vulnerablePluginJar();
        JarModel jar = new JarLoader(p).load("app.jar", jarBytes);

        Path list = cacheDir.resolve("good.txt");
        Files.writeString(list, jar.sha256() + "\n");
        p.getSupplyChain().setReputationEnabled(true);
        p.getSupplyChain().setKnownGoodSource(list.toString());

        AnalysisContext ctx = new AnalysisContext(jar, List.<ClassScan>of());
        new ReputationAnalyzer(p, new ReputationService(p)).analyze(ctx);

        Finding good = ctx.findings().stream()
                .filter(f -> f.ruleId().equals("REPUTATION_KNOWN_GOOD"))
                .findFirst().orElse(null);
        assertThat(good).isNotNull();
        assertThat(good.severity()).isEqualTo(Severity.INFO);
    }
}
