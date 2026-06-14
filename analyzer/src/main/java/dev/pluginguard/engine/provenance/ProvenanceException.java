package dev.pluginguard.engine.provenance;

/**
 * Signals that an official source could not be reached or returned an unusable response (after
 * retries). It is distinct from a clean "not found" (HTTP 404), which the clients model as an empty
 * result. The verifier catches this per source so one source's outage never fails the whole check.
 */
public class ProvenanceException extends RuntimeException {

    public ProvenanceException(String message) {
        super(message);
    }

    public ProvenanceException(String message, Throwable cause) {
        super(message, cause);
    }
}
