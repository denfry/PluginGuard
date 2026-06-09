package dev.pluginguard.engine.model;

import java.time.Instant;
import java.util.List;

/**
 * The complete security report for one analyzed JAR. This record is serialized directly to JSON
 * and consumed by the web UI, so field names are part of the API contract.
 *
 * @param id               opaque report id (used for {@code GET /api/scan/{id}})
 * @param fileName         original uploaded filename
 * @param sha256           SHA-256 of the uploaded bytes
 * @param sizeBytes        size of the uploaded file in bytes
 * @param platform         detected plugin platform (Paper/Bukkit, BungeeCord, Velocity, Unknown)
 * @param mainClass        declared main class, or {@code null}
 * @param mcApiVersion     declared Minecraft api-version, or {@code null}
 * @param score            security score, 0–100 (higher is safer)
 * @param verdict          risk band derived from the score
 * @param obfuscationScore obfuscation score, 0–100 (higher is more obfuscated)
 * @param counts           finding counts per severity
 * @param pluginInfo       parsed plugin descriptor, or {@code null} if none found
 * @param findings         all findings, sorted most-severe first
 * @param summaries        aggregated network / filesystem / dependency views
 * @param notes            engine-level notes (e.g. guard limits hit, nested jars skipped)
 * @param analyzedAt       analysis timestamp
 * @param durationMs       analysis wall-clock duration in milliseconds
 * @param engineVersion    analyzer engine version
 */
public record ScanResult(
        String id,
        String fileName,
        String sha256,
        long sizeBytes,
        String platform,
        String mainClass,
        String mcApiVersion,
        int score,
        Verdict verdict,
        int obfuscationScore,
        SeverityCounts counts,
        PluginInfo pluginInfo,
        List<Finding> findings,
        Summaries summaries,
        List<String> notes,
        Instant analyzedAt,
        long durationMs,
        String engineVersion) {
}
