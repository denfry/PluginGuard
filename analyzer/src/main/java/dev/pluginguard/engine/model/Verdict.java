package dev.pluginguard.engine.model;

/**
 * Overall risk verdict derived from the security score. Bands intentionally match the
 * concept spec: 0–39 critical/high, 40–69 medium, 70–89 low, 90–100 minimal.
 */
public enum Verdict {
    MINIMAL_RISK("Minimal Risk"),
    LOW_RISK("Low Risk"),
    MEDIUM_RISK("Medium Risk"),
    HIGH_RISK("High Risk"),
    CRITICAL_RISK("Critical Risk");

    private final String label;

    Verdict(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }

    /** Maps a 0–100 score to a verdict band. */
    public static Verdict fromScore(int score) {
        if (score < 25) return CRITICAL_RISK;
        if (score < 40) return HIGH_RISK;
        if (score < 70) return MEDIUM_RISK;
        if (score < 90) return LOW_RISK;
        return MINIMAL_RISK;
    }

    /**
     * Combines the numeric score with the worst finding severity, so the presence of a high or
     * critical finding floors the verdict regardless of an otherwise good score. The more severe
     * of the two assessments wins.
     */
    public static Verdict from(int score, SeverityCounts counts) {
        Verdict band = fromScore(score);
        Verdict floor;
        if (counts.critical() > 0) {
            floor = CRITICAL_RISK;
        } else if (counts.high() > 0) {
            floor = MEDIUM_RISK;
        } else {
            floor = MINIMAL_RISK;
        }
        // Higher ordinal == more severe.
        return band.ordinal() >= floor.ordinal() ? band : floor;
    }
}
