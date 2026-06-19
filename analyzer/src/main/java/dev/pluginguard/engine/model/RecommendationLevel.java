package dev.pluginguard.engine.model;

/** Overall install guidance synthesized across axes (most to least favorable). */
public enum RecommendationLevel {
    SAFE_TO_INSTALL("Safe to install"),
    INSTALL_WITH_CARE("Install with care"),
    RISKY("Risky"),
    AVOID("Avoid"),
    DO_NOT_INSTALL("Do not install");

    private final String displayName;

    RecommendationLevel(String displayName) {
        this.displayName = displayName;
    }

    public String displayName() {
        return displayName;
    }
}
