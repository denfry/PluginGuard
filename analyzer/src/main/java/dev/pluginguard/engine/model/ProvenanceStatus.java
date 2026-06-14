package dev.pluginguard.engine.model;

/**
 * Lifecycle / outcome of the optional online authenticity verification for a report. Like the
 * dynamic sandbox, online verification (when enabled) is an asynchronous job whose status the
 * {@code GET /api/scan/{id}} endpoint surfaces as it progresses; unlike the sandbox, its terminal
 * states encode the <em>verdict</em> of the comparison against the official source.
 */
public enum ProvenanceStatus {
    /** The online verification feature is turned off (the default). */
    DISABLED,
    /** Enabled and queued, not yet started. */
    PENDING,
    /** Currently querying official sources / downloading the official release. */
    RUNNING,
    /** Exact hash match on an official source — this is byte-for-byte the genuine release. */
    VERIFIED,
    /** The plugin + version was found on an official source but the bytes differ — a modified copy. */
    TAMPERED,
    /** The plugin could not be found on any queried official source, so it cannot be verified. */
    NOT_FOUND,
    /** Enabled but skipped for this file (e.g. no plugin name/version to look up). */
    UNVERIFIED,
    /** Enabled but not entitled for this caller (e.g. free tier), so no lookup was performed. */
    SKIPPED,
    /** The job started but failed (network/parse error); no reliable verdict. */
    FAILED
}
