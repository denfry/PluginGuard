package dev.pluginguard.engine.provenance;

/**
 * A candidate official release resolved by name/version (or repo) from one source, before the byte
 * comparison. When {@code hash} is known (Modrinth/Hangar expose it) the verifier compares hashes
 * without downloading; when it is {@code null} (GitHub) the verifier downloads {@code downloadUrl}
 * and compares the bytes directly.
 *
 * @param source       display name of the source (e.g. {@code Modrinth})
 * @param projectName  the official project's display name
 * @param projectUrl   human-openable URL for the project / release
 * @param version      the matched official version
 * @param fileName     the official artifact's file name, or {@code null}
 * @param hashAlgo     the algorithm of {@link #hash} ({@code sha512}/{@code sha256}/{@code sha1}), or {@code null}
 * @param hash         the official artifact's hash, or {@code null} when it must be downloaded to compare
 * @param downloadUrl  direct download URL of the official artifact
 */
public record OfficialRelease(
        String source,
        String projectName,
        String projectUrl,
        String version,
        String fileName,
        String hashAlgo,
        String hash,
        String downloadUrl) {
}
