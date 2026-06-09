package dev.pluginguard.engine.model;

import java.util.List;
import java.util.Objects;

/**
 * A single observation produced by an analyzer.
 *
 * @param ruleId         stable identifier of the rule that produced this finding (e.g. {@code BYTECODE_PROCESS_EXEC});
 *                       used by {@link dev.pluginguard.scoring.ScoreCalculator} for per-rule deduction caps
 * @param category       high-level grouping for UI bucketing
 * @param severity       seriousness level
 * @param title          short human-readable headline
 * @param description    plain-language explanation aimed at a server admin, not a developer
 * @param recommendation what the admin should do about it
 * @param location       where it was found (class / method / resource path); may be {@code null}
 * @param evidence       the concrete matched value (URL, call, string); may be {@code null}
 * @param scoreImpact    points to deduct from the 100-point start (positive magnitude; 0 for INFO)
 * @param nestedPath     jar-chain the finding came from for nested archives
 *                       (e.g. {@code bundled/lib.jar!/}); {@code null} for the top-level JAR
 * @param relatedRuleIds for correlation (COMBO) findings, the rule ids whose combination raised this
 *                       finding; empty for ordinary findings
 */
public record Finding(
        String ruleId,
        Category category,
        Severity severity,
        String title,
        String description,
        String recommendation,
        String location,
        String evidence,
        int scoreImpact,
        String nestedPath,
        List<String> relatedRuleIds) {

    public Finding {
        Objects.requireNonNull(ruleId, "ruleId");
        Objects.requireNonNull(category, "category");
        Objects.requireNonNull(severity, "severity");
        Objects.requireNonNull(title, "title");
        relatedRuleIds = relatedRuleIds == null ? List.of() : List.copyOf(relatedRuleIds);
    }

    public static Builder builder(String ruleId, Category category, Severity severity) {
        return new Builder(ruleId, category, severity);
    }

    /** Fluent builder so analyzers can omit optional fields cleanly. */
    public static final class Builder {
        private final String ruleId;
        private final Category category;
        private final Severity severity;
        private String title = "";
        private String description = "";
        private String recommendation = "";
        private String location;
        private String evidence;
        private int scoreImpact;
        private String nestedPath;
        private List<String> relatedRuleIds = List.of();

        private Builder(String ruleId, Category category, Severity severity) {
            this.ruleId = ruleId;
            this.category = category;
            this.severity = severity;
        }

        public Builder title(String v) { this.title = v; return this; }
        public Builder description(String v) { this.description = v; return this; }
        public Builder recommendation(String v) { this.recommendation = v; return this; }
        public Builder location(String v) { this.location = v; return this; }
        public Builder evidence(String v) { this.evidence = v; return this; }
        public Builder scoreImpact(int v) { this.scoreImpact = v; return this; }
        public Builder nestedPath(String v) { this.nestedPath = v; return this; }
        public Builder relatedRuleIds(List<String> v) { this.relatedRuleIds = v; return this; }

        public Finding build() {
            return new Finding(ruleId, category, severity, title, description,
                    recommendation, location, evidence, scoreImpact, nestedPath, relatedRuleIds);
        }
    }
}
