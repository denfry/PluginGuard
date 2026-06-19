package dev.pluginguard.engine.model;

/**
 * A top-level dimension the report scores independently. SECURITY is the original score; the others
 * are answered by their own analyzers. Only SECURITY and PERFORMANCE are populated today.
 */
public enum Axis {
    SECURITY("Security"),
    PERFORMANCE("Performance"),
    COMPATIBILITY("Compatibility"),
    HEALTH("Code health"),
    LICENSE("Legal / license");

    private final String displayName;

    Axis(String displayName) {
        this.displayName = displayName;
    }

    public String displayName() {
        return displayName;
    }
}
