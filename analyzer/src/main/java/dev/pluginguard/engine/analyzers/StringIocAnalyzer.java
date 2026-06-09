package dev.pluginguard.engine.analyzers;

import dev.pluginguard.engine.AnalysisContext;
import dev.pluginguard.engine.Analyzer;
import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.model.Category;
import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.ResourceFile;
import dev.pluginguard.engine.model.Severity;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extracts indicators of compromise from string constants (constant pool) and text resources:
 * URLs and webhooks, IP literals, shell-command and credential-theft markers, and long base64-like
 * blobs. Also populates the Network and Filesystem summary cards.
 */
@Component
@Order(40)
public class StringIocAnalyzer implements Analyzer {

    private static final Pattern URL = Pattern.compile("https?://([^/\\s\"'<>\\\\)]+)(\\S*)", Pattern.CASE_INSENSITIVE);
    private static final Pattern IPV4 = Pattern.compile("\\b(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\b");
    private static final Pattern BASE64_BLOB = Pattern.compile("[A-Za-z0-9+/]{120,}={0,2}");
    private static final Pattern WIN_PATH = Pattern.compile("[A-Za-z]:\\\\[^\"'\\s]{2,}");

    private static final Set<String> TEXT_EXTENSIONS = Set.of(
            ".yml", ".yaml", ".json", ".txt", ".properties", ".conf", ".cfg", ".ini",
            ".csv", ".md", ".sql", ".js", ".html", ".xml", ".toml", ".env");

    private static final int MAX_PER_RULE = 20;
    private static final int BASE64_FINDING_THRESHOLD = 5;

    @Override
    public String name() {
        return "string-ioc";
    }

    @Override
    public void analyze(AnalysisContext ctx) {
        Set<String> seen = new HashSet<>();
        int base64Count = 0;

        // Class constant-pool strings.
        for (ClassScan scan : ctx.classScans()) {
            for (String s : scan.stringConstants()) {
                base64Count += scanUnit(ctx, seen, scan.dottedName(), s);
            }
        }

        // Text resources.
        for (ResourceFile res : ctx.jar().resources()) {
            if (isTextResource(res.name())) {
                base64Count += scanUnit(ctx, seen, res.name(), res.text());
            }
        }

        if (base64Count >= BASE64_FINDING_THRESHOLD) {
            ctx.add(Finding.builder("IOC_BASE64_BLOBS", Category.STRING_IOC, Severity.MEDIUM)
                    .title("Many encoded (base64-like) strings")
                    .description("Found " + base64Count + " long base64-like strings. These can be encoded payloads, "
                            + "configuration, or simply embedded resources — but a high count alongside class loading "
                            + "or decryption is a common way to hide malicious code.")
                    .recommendation("Review what these blobs decode to if the plugin also loads classes or decrypts data.")
                    .evidence(base64Count + " blobs")
                    .scoreImpact(8)
                    .build());
        }
    }

    /** Returns the number of base64-like blobs found in this unit. */
    private int scanUnit(AnalysisContext ctx, Set<String> seen, String source, String text) {
        if (text == null || text.isEmpty()) {
            return 0;
        }
        String lower = text.toLowerCase(Locale.ROOT);

        // URLs → network summary + webhook/telegram findings.
        Matcher um = URL.matcher(text);
        while (um.find()) {
            String host = um.group(1);
            String full = um.group();
            ctx.addNetworkIndicator(host);
            String fl = full.toLowerCase(Locale.ROOT);
            if (fl.contains("/api/webhooks") || (host.toLowerCase(Locale.ROOT).contains("discord") && fl.contains("webhook"))) {
                emit(ctx, seen, Finding.builder("IOC_DISCORD_WEBHOOK", Category.NETWORK, Severity.MEDIUM)
                        .title("Discord webhook URL")
                        .description("The code references a Discord webhook. This is often legitimate (moderation/log "
                                + "relays), but is also used to exfiltrate data to an attacker.")
                        .recommendation("Make sure sending data to Discord is documented and configurable.")
                        .location(source).evidence(truncate(full)).scoreImpact(20).build());
            } else if (host.toLowerCase(Locale.ROOT).contains("api.telegram.org")) {
                emit(ctx, seen, Finding.builder("IOC_TELEGRAM_API", Category.NETWORK, Severity.MEDIUM)
                        .title("Telegram Bot API URL")
                        .description("The code references the Telegram Bot API, sometimes used as an exfiltration channel.")
                        .recommendation("Confirm the plugin documents its Telegram integration.")
                        .location(source).evidence(truncate(full)).scoreImpact(20).build());
            }
        }

        // IPv4 literals → network summary + finding for public addresses.
        Matcher im = IPV4.matcher(text);
        while (im.find()) {
            String ip = im.group();
            if (isValidPublicIp(im)) {
                ctx.addNetworkIndicator(ip);
                emit(ctx, seen, Finding.builder("IOC_HARDCODED_IP", Category.NETWORK, Severity.MEDIUM)
                        .title("Hard-coded public IP address")
                        .description("A literal public IP address (" + ip + ") is embedded in the code. Hard-coded IPs "
                                + "can point to a command-and-control or download server.")
                        .recommendation("Check what this address is contacted for.")
                        .location(source).evidence(ip).scoreImpact(12).build());
            }
        }

        // Shell / LOLBIN command markers.
        scanMarkers(ctx, seen, source, lower,
                List.of("cmd.exe", "powershell", "/bin/sh", "/bin/bash", "certutil", "bitsadmin", "wget ", "curl "),
                "IOC_SHELL_COMMAND", Category.PROCESS, Severity.HIGH, 25,
                "Shell-command string present",
                "A string strongly associated with running shell commands or downloading files was found.",
                "Combined with process-execution bytecode, this is a serious red flag.");

        // Credential / token theft targets.
        scanMarkers(ctx, seen, source, lower,
                List.of("launcher_accounts.json", "launcher_profiles.json", "id_rsa", "/.ssh/", "\\.ssh\\"),
                "IOC_CREDENTIAL_TARGET", Category.FILESYSTEM, Severity.HIGH, 30,
                "Credential-theft target string",
                "A path commonly targeted by credential/account stealers (e.g. Minecraft launcher accounts, SSH keys) "
                        + "was found.",
                "Strong indicator of an account/session stealer — do not install without thorough review.");

        // Sensitive local directories.
        scanMarkers(ctx, seen, source, lower,
                List.of(".minecraft", "appdata", "%appdata%"),
                "IOC_SENSITIVE_PATH", Category.FILESYSTEM, Severity.MEDIUM, 10,
                "Reference to a sensitive local directory",
                "The code references a sensitive user directory (.minecraft / AppData). Plugins normally only touch "
                        + "their own folder under plugins/.",
                "Investigate why the plugin reaches outside the server directory.");

        // Filesystem summary: Windows paths and plugin-relative paths.
        Matcher wp = WIN_PATH.matcher(text);
        while (wp.find()) {
            ctx.addFilesystemPath(truncate(wp.group()));
        }
        if (text.contains("plugins/") || text.contains("plugins\\")) {
            ctx.addFilesystemPath(text.length() <= 80 ? text.trim() : "plugins/...");
        }

        // base64-like blob count.
        int blobs = 0;
        Matcher bm = BASE64_BLOB.matcher(text);
        while (bm.find()) {
            blobs++;
        }
        return blobs;
    }

    private void scanMarkers(AnalysisContext ctx, Set<String> seen, String source, String lowerText,
                             List<String> markers, String ruleId, Category category, Severity severity,
                             int scoreImpact, String title, String description, String recommendation) {
        for (String marker : markers) {
            if (lowerText.contains(marker)) {
                emit(ctx, seen, Finding.builder(ruleId, category, severity)
                        .title(title)
                        .description(description)
                        .recommendation(recommendation)
                        .location(source)
                        .evidence(marker.trim())
                        .scoreImpact(scoreImpact)
                        .build());
            }
        }
    }

    /** De-duplicates by rule+evidence and caps the number of findings per rule. */
    private void emit(AnalysisContext ctx, Set<String> seen, Finding finding) {
        String key = finding.ruleId() + "|" + finding.evidence();
        if (!seen.add(key)) {
            return;
        }
        long countForRule = ctx.findings().stream()
                .filter(f -> f.ruleId().equals(finding.ruleId()))
                .count();
        if (countForRule >= MAX_PER_RULE) {
            return;
        }
        ctx.add(finding);
    }

    private boolean isValidPublicIp(Matcher m) {
        int a = Integer.parseInt(m.group(1));
        int b = Integer.parseInt(m.group(2));
        int c = Integer.parseInt(m.group(3));
        int d = Integer.parseInt(m.group(4));
        if (a > 255 || b > 255 || c > 255 || d > 255) {
            return false; // not a real IPv4 (e.g. a version string)
        }
        if (a == 0 || a == 127 || a == 10 || a == 255) {
            return false; // this/loopback/private/broadcast
        }
        if (a == 192 && b == 168) {
            return false;
        }
        if (a == 172 && b >= 16 && b <= 31) {
            return false;
        }
        if (a == 169 && b == 254) {
            return false; // link-local
        }
        return true;
    }

    private boolean isTextResource(String name) {
        String lower = name.toLowerCase(Locale.ROOT);
        for (String ext : TEXT_EXTENSIONS) {
            if (lower.endsWith(ext)) {
                return true;
            }
        }
        return false;
    }

    private static String truncate(String s) {
        return s.length() <= 120 ? s : s.substring(0, 117) + "...";
    }
}
