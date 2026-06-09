package dev.pluginguard.api;

import dev.pluginguard.engine.AnalysisEngine;
import dev.pluginguard.engine.model.Category;
import dev.pluginguard.engine.model.Dependency;
import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.PluginInfo;
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
                        .scoreImpact(5).build());

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
        return new ScanResult(
                "demo",
                "ChatGuard-1.4.2.jar",
                "92a7f4b1c0d3e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0",
                1_887_436L,
                "Bukkit/Spigot/Paper",
                "dev.chatguard.ChatGuardPlugin",
                "1.21",
                score,
                Verdict.from(score, counts),
                28,
                counts,
                info,
                findings,
                summaries,
                List.of("This is a demonstration report with illustrative data."),
                Instant.parse("2026-06-09T12:00:00Z"),
                42L,
                AnalysisEngine.ENGINE_VERSION);
    }
}
