package dev.pluginguard.engine;

/** Thrown when an upload cannot be analyzed at all (e.g. unreadable, empty). */
public class AnalysisException extends RuntimeException {
    public AnalysisException(String message) {
        super(message);
    }

    public AnalysisException(String message, Throwable cause) {
        super(message, cause);
    }
}
