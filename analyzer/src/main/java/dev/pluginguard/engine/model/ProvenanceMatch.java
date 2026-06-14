package dev.pluginguard.engine.model;

/**
 * The official release this artifact was compared against. Produced either by a direct hash lookup
 * (then {@link #hashMatched()} is {@code true} and this <em>is</em> the genuine build) or by
 * resolving the declared plugin name + version on an official source (then the hashes are compared).
 * Part of the JSON API contract.
 *
 * @param source           which source produced the match (e.g. {@code Modrinth}, {@code Hangar}, {@code GitHub})
 * @param projectName      the official project's display name
 * @param projectUrl       a human-openable URL for the project / release
 * @param matchedVersion   the official version that was matched, or {@code null} if matched purely by hash
 * @param officialFileName the official artifact's file name, or {@code null}
 * @param officialHash     the official artifact's hash we compared against (sha512/sha256/sha1), or {@code null}
 * @param downloadUrl      direct download URL of the official artifact (used for the structural diff), or {@code null}
 * @param hashMatched      {@code true} when the uploaded bytes hash-match this official release exactly
 */
public record ProvenanceMatch(
        String source,
        String projectName,
        String projectUrl,
        String matchedVersion,
        String officialFileName,
        String officialHash,
        String downloadUrl,
        boolean hashMatched) {
}
