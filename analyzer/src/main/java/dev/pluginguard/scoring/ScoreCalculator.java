package dev.pluginguard.scoring;

import dev.pluginguard.engine.model.Category;
import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.Severity;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Turns findings into a 0–100 security score (higher = safer).
 *
 * <p>Starting from 100, each distinct rule deducts its {@code scoreImpact} once, plus a bounded
 * surcharge for repeated occurrences (up to +75% of the base impact). Grouping by rule prevents a
 * single repeated behaviour (e.g. 25 HTTP calls) from dominating the score, while still letting a
 * <em>variety</em> of dangerous behaviours drive a clearly-malicious plugin to zero.
 *
 * <p>Correlation ({@code COMBO}) findings — which only fire when several dangerous capabilities are
 * wired together — deduct extra, and the presence of any {@code CRITICAL} finding caps the numeric
 * score so it can never look "mostly fine" when a critical behaviour was detected.
 */
@Component
public class ScoreCalculator {

    /** Extra occurrences beyond the first that still add to the deduction. */
    private static final int MAX_EXTRA_OCCURRENCES = 3;
    private static final double EXTRA_OCCURRENCE_WEIGHT = 0.25;

    /** Correlation findings are the strongest signal, so their deduction is amplified. */
    private static final double COMBO_MULTIPLIER = 1.3;

    /** A critical finding cannot coexist with a reassuring score. */
    private static final int CRITICAL_SCORE_CEILING = 15;
    private static final int HIGH_SCORE_CEILING = 55;

    public int score(List<Finding> findings) {
        Map<String, List<Finding>> byRule = findings.stream()
                .collect(Collectors.groupingBy(Finding::ruleId));

        double deduction = 0;
        for (List<Finding> group : byRule.values()) {
            int impact = group.stream().mapToInt(Finding::scoreImpact).max().orElse(0);
            if (impact == 0) {
                continue;
            }
            int extraOccurrences = Math.min(group.size() - 1, MAX_EXTRA_OCCURRENCES);
            double base = impact + extraOccurrences * impact * EXTRA_OCCURRENCE_WEIGHT;
            if (group.get(0).category() == Category.COMBO) {
                base *= COMBO_MULTIPLIER;
            }
            deduction += base;
        }

        int score = (int) Math.round(100 - deduction);
        score = Math.max(0, Math.min(100, score));

        // Floor the numeric score to match the worst severity so the verdict and number agree.
        boolean hasCritical = findings.stream().anyMatch(f -> f.severity() == Severity.CRITICAL);
        boolean hasHigh = findings.stream().anyMatch(f -> f.severity() == Severity.HIGH);
        if (hasCritical) {
            score = Math.min(score, CRITICAL_SCORE_CEILING);
        } else if (hasHigh) {
            score = Math.min(score, HIGH_SCORE_CEILING);
        }
        return score;
    }
}
