package dev.pluginguard.scoring;

import dev.pluginguard.engine.model.Axis;
import dev.pluginguard.engine.model.AxisScore;
import dev.pluginguard.engine.model.Category;
import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.Severity;
import dev.pluginguard.engine.model.SeverityCounts;
import dev.pluginguard.engine.model.Verdict;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Turns findings into a 0–100 score (higher = safer); also scores each axis independently via
 * {@link #scoreByAxis(java.util.List)}.
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
        return applyCeilings(deduct(findings), findings);
    }

    /** One {@link AxisScore} per axis that has at least one finding, ordered by {@link Axis} ordinal. */
    public List<AxisScore> scoreByAxis(List<Finding> findings) {
        List<AxisScore> out = new ArrayList<>();
        for (Axis axis : Axis.values()) {
            List<Finding> axisFindings = findings.stream()
                    .filter(f -> f.category().axis() == axis)
                    .toList();
            if (axisFindings.isEmpty()) {
                continue;
            }
            int score = applyCeilings(deduct(axisFindings), axisFindings);
            SeverityCounts counts = SeverityCounts.from(axisFindings);
            Verdict verdict = Verdict.from(score, counts);
            out.add(new AxisScore(axis, score, verdict, counts, headline(axis, counts)));
        }
        return out;
    }

    /** Raw 0–100 score from the per-rule deduction model, before severity ceilings. */
    private double rawDeduction(List<Finding> findings) {
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
        return deduction;
    }

    private int deduct(List<Finding> findings) {
        int score = (int) Math.round(100 - rawDeduction(findings));
        return Math.max(0, Math.min(100, score));
    }

    private int applyCeilings(int score, List<Finding> findings) {
        boolean hasCritical = findings.stream().anyMatch(f -> f.severity() == Severity.CRITICAL);
        boolean hasHigh = findings.stream().anyMatch(f -> f.severity() == Severity.HIGH);
        if (hasCritical) {
            return Math.min(score, CRITICAL_SCORE_CEILING);
        } else if (hasHigh) {
            return Math.min(score, HIGH_SCORE_CEILING);
        }
        return score;
    }

    private static String headline(Axis axis, SeverityCounts counts) {
        int serious = counts.critical() + counts.high();
        if (serious > 0) {
            return serious + " serious " + axis.displayName().toLowerCase() + " issue(s)";
        }
        if (counts.total() > 0) {
            return counts.total() + " minor " + axis.displayName().toLowerCase() + " note(s)";
        }
        return "No " + axis.displayName().toLowerCase() + " issues found";
    }
}
