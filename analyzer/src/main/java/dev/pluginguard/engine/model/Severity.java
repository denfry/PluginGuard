package dev.pluginguard.engine.model;

/**
 * Severity of a {@link Finding}, ordered from most to least serious. The frontend maps each
 * level to a colour; scoring uses the level only as a tiebreaker — concrete point deductions
 * are driven by the finding's {@code scoreImpact}.
 */
public enum Severity {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,
    INFO
}
