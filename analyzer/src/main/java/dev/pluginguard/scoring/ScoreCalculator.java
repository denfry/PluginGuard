package dev.pluginguard.scoring;

import dev.pluginguard.engine.model.Finding;
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
 */
@Component
public class ScoreCalculator {

    /** Extra occurrences beyond the first that still add to the deduction. */
    private static final int MAX_EXTRA_OCCURRENCES = 3;
    private static final double EXTRA_OCCURRENCE_WEIGHT = 0.25;

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
            deduction += impact + extraOccurrences * impact * EXTRA_OCCURRENCE_WEIGHT;
        }

        int score = (int) Math.round(100 - deduction);
        return Math.max(0, Math.min(100, score));
    }
}
