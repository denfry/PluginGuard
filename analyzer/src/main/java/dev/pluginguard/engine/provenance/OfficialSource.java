package dev.pluginguard.engine.provenance;

import dev.pluginguard.engine.model.ProvenanceMatch;

import java.util.Optional;

/**
 * An official place a Minecraft plugin/mod is published, against which an uploaded jar can be checked.
 * Implementations fail soft on a clean miss (empty {@link Optional}) and throw
 * {@link ProvenanceException} only when they genuinely could not reach the source.
 */
public interface OfficialSource {

    /** Human-readable source name shown in the report (e.g. {@code Modrinth}). */
    String displayName();

    /**
     * Looks the file up directly by its hash. A hit means these exact bytes are a published official
     * release — an authoritative {@code VERIFIED}. Only sources with a hash→release index (Modrinth)
     * implement this; others return empty.
     */
    default Optional<ProvenanceMatch> lookupByHash(String sha1, String sha512) {
        return Optional.empty();
    }

    /**
     * Resolves the official release matching the declared identity (name + version, or repo), so the
     * verifier can compare it to the upload. Empty means this source does not list it.
     */
    Optional<OfficialRelease> findRelease(Identity id);
}
