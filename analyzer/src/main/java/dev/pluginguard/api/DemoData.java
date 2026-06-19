package dev.pluginguard.api;

import dev.pluginguard.engine.AnalysisEngine;
import dev.pluginguard.engine.model.ArtifactType;
import dev.pluginguard.engine.model.Axis;
import dev.pluginguard.engine.model.AxisScore;
import dev.pluginguard.engine.model.BehaviorEvent;
import dev.pluginguard.engine.model.Category;
import dev.pluginguard.engine.model.Dependency;
import dev.pluginguard.engine.model.DynamicFinding;
import dev.pluginguard.engine.model.DynamicFinding.DynamicCorrelation;
import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.PluginInfo;
import dev.pluginguard.engine.model.Recommendation;
import dev.pluginguard.engine.model.RecommendationLevel;
import dev.pluginguard.engine.model.SandboxReport;
import dev.pluginguard.engine.model.SandboxStatus;
import dev.pluginguard.engine.model.ScanResult;
import dev.pluginguard.engine.model.Severity;
import dev.pluginguard.engine.model.SeverityCounts;
import dev.pluginguard.engine.model.Summaries;
import dev.pluginguard.engine.model.Verdict;

import java.time.Instant;
import java.util.List;

/** A fixed, illustrative report served at {@code GET /api/demo} and rendered on the web demo page. */
public final class DemoData {

    private DemoData() {
    }

    public static ScanResult sample() {
        List<Finding> findings = List.of(
                Finding.builder("IOC_DISCORD_WEBHOOK", Category.NETWORK, Severity.HIGH)
                        .title("External Discord webhook")
                        .description("The plugin sends data to an external Discord webhook from its moderation logger.")
                        .recommendation("Make sure this is documented and configurable before production use.")
                        .location("dev.chatguard.webhook.WebhookClient#sendModerationLog")
                        .evidence("https://discord.com/api/webhooks/****")
                        .scoreImpact(20).build(),
                Finding.builder("BYTECODE_CLASS_FORNAME", Category.REFLECTION, Severity.MEDIUM)
                        .title("Reflection used to access server internals")
                        .description("Class.forName() is used to reach version-specific (NMS) server classes.")
                        .recommendation("Common in Minecraft plugins, but should be reviewed.")
                        .location("dev.chatguard.internal.NMSResolver#resolve")
                        .evidence("java.lang.Class.forName()")
                        .scoreImpact(6).build(),
                Finding.builder("BYTECODE_HTTP_URLCONN", Category.NETWORK, Severity.LOW)
                        .title("Makes HTTP requests")
                        .description("Performs HTTP requests, e.g. for update checks against GitHub.")
                        .recommendation("Check the destination — see the Network summary.")
                        .location("dev.chatguard.update.UpdateChecker#check")
                        .evidence("java.net.HttpURLConnection")
                        .scoreImpact(8).build(),
                Finding.builder("YML_WILDCARD_PERMISSION", Category.PLUGIN_YML, Severity.LOW)
                        .title("Broad wildcard permission")
                        .description("Permission 'chatguard.*' can implicitly grant many child nodes.")
                        .recommendation("Review which nodes the wildcard covers.")
                        .location("plugin.yml")
                        .evidence("chatguard.*")
                        .scoreImpact(5).build(),
                Finding.builder("PROVENANCE_UNVERIFIED", Category.PROVENANCE, Severity.LOW)
                        .title("Source not verified")
                        .description("No GitHub repository or signed build was provided for this file.")
                        .recommendation("Prefer plugins from official, verifiable sources.")
                        .scoreImpact(5).build(),
                Finding.builder("PERF_BLOCKING_IO_HOT_PATH", Category.PERFORMANCE, Severity.HIGH)
                        .title("Database query on the server thread in a hot path")
                        .description("Runs a synchronous database query from a frequently-fired event — this can stall the server tick under load.")
                        .recommendation("Move the query to an async task and cache the result.")
                        .location("dev.chatguard.listener.MoveListener#onMove")
                        .evidence("java.sql.Statement.executeQuery")
                        .scoreImpact(20).build());

        PluginInfo info = new PluginInfo(
                "plugin.yml", "ChatGuard", "1.4.2", "dev.chatguard.ChatGuardPlugin", "1.21",
                List.of("chatguard-dev"),
                List.of("mute", "warn", "chatclear"),
                List.of("chatguard.admin", "chatguard.bypass", "chatguard.*"),
                List.of("LuckPerms"), List.of("Vault"), List.of());

        Summaries summaries = new Summaries(
                List.of("discord.com", "api.github.com"),
                List.of("plugins/ChatGuard/config.yml", "plugins/ChatGuard/logs/"),
                List.of(new Dependency("com.google.code.gson:gson", "2.10.1", "pom.properties"),
                        new Dependency("com.squareup.okhttp3:okhttp", "4.12.0", "pom.properties")),
                64, 412);

        int score = 78;
        SeverityCounts counts = SeverityCounts.from(findings);
        SeverityCounts securityCounts = SeverityCounts.from(
                findings.stream().filter(f -> f.category().axis() == Axis.SECURITY).toList());

        List<AxisScore> axes = List.of(
                new AxisScore(
                        Axis.SECURITY, 78,
                        Verdict.from(78, securityCounts), securityCounts, "1 serious security issue(s)"),
                new AxisScore(
                        Axis.PERFORMANCE, 55,
                        Verdict.MEDIUM_RISK, new SeverityCounts(0, 1, 0, 0, 0),
                        "1 serious performance issue(s)"));

        Recommendation recommendation = new Recommendation(
                RecommendationLevel.RISKY,
                "Security is fine, but a database query on the server thread is a high lag risk — review before installing.",
                List.of(
                        "Security: Low Risk — 1 serious security issue(s)",
                        "Performance: Medium Risk — 1 serious performance issue(s)"));

        SandboxReport sandbox = new SandboxReport(
                SandboxStatus.COMPLETED,
                "docker",
                Instant.parse("2026-06-09T12:00:01Z"),
                Instant.parse("2026-06-09T12:00:06Z"),
                4800L,
                Severity.HIGH,
                7,
                List.of(
                        new DynamicFinding("DYNAMIC_NETWORK_CONNECT", "NETWORK_CONNECT", Severity.HIGH,
                                "Opened an outbound connection", "discord.com:443", true, 1,
                                DynamicCorrelation.CONFIRMS_STATIC,
                                "While running, the plugin tried to reach discord.com — blocked by the network-isolated "
                                        + "sandbox. This confirms the statically-detected webhook.",
                                "Confirm the destination is expected — see the Network summary."),
                        new DynamicFinding("DYNAMIC_REFLECTION", "REFLECTION", Severity.MEDIUM,
                                "Used reflection", "java.lang.Class.forName", false, 3,
                                DynamicCorrelation.CONFIRMS_STATIC,
                                "The plugin used reflection at runtime to reach version-specific server classes.",
                                "Common in Minecraft plugins, but review the targets.")),
                List.of(
                        new BehaviorEvent("LIFECYCLE", "onEnable", null, null, false),
                        new BehaviorEvent("REFLECTION", "java.lang.Class.forName", "observed at an instrumented call site", null, false),
                        new BehaviorEvent("NETWORK_CONNECT", "discord.com:443", "blocked by sandbox SecurityManager", null, true),
                        new BehaviorEvent("LIFECYCLE", "onDisable", null, null, false)),
                List.of(
                        "A sandbox observes only the code paths the harness triggered; behavior gated on a "
                                + "specific date, environment or in-game event can stay dormant.",
                        "Malware can detect that it is being analyzed and deliberately behave benignly (sandbox evasion).",
                        "Blocked actions are still strong evidence of intent — the plugin tried, the sandbox stopped it."),
                null);

        return new ScanResult(
                "demo",
                "ChatGuard-1.4.2.jar",
                "92a7f4b1c0d3e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0",
                1_887_436L,
                "Bukkit/Spigot/Paper",
                ArtifactType.PLUGIN_BUKKIT,
                "dev.chatguard.ChatGuardPlugin",
                "1.21",
                score,
                Verdict.from(score, counts),
                28,
                counts,
                info,
                findings,
                summaries,
                List.of("This is a demonstration report with illustrative data.",
                        "Dynamic sandbox observed 7 behavior event(s); 2 dynamic finding(s)."),
                Instant.parse("2026-06-09T12:00:00Z"),
                42L,
                AnalysisEngine.ENGINE_VERSION,
                sandbox,
                axes,
                recommendation);
    }
}
