package dev.pluginguard.scoring;

import dev.pluginguard.engine.model.Axis;
import dev.pluginguard.engine.model.AxisScore;
import dev.pluginguard.engine.model.Recommendation;
import dev.pluginguard.engine.model.RecommendationLevel;
import dev.pluginguard.engine.model.Verdict;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;

/** Synthesizes per-axis verdicts into one install recommendation, with security holding veto power. */
@Component
public class RecommendationCalculator {

    public Recommendation recommend(List<AxisScore> axes) {
        Optional<AxisScore> security = axes.stream().filter(a -> a.axis() == Axis.SECURITY).findFirst();
        Verdict sec = security.map(AxisScore::verdict).orElse(Verdict.MINIMAL_RISK);

        List<String> perAxis = new ArrayList<>();
        for (AxisScore a : axes) {
            perAxis.add(a.axis().displayName() + ": " + a.verdict().getLabel() + " — " + a.headline());
        }

        // Security veto.
        if (sec == Verdict.CRITICAL_RISK) {
            return new Recommendation(RecommendationLevel.DO_NOT_INSTALL,
                    "Critical security risk — do not install this artifact.", perAxis);
        }
        if (sec == Verdict.HIGH_RISK) {
            return new Recommendation(RecommendationLevel.AVOID,
                    "High security risk — avoid unless you fully trust the source.", perAxis);
        }

        // Worst non-security axis drives the rest, by effective severity level.
        AxisScore worst = axes.stream()
                .filter(a -> a.axis() != Axis.SECURITY)
                .max(Comparator.comparingInt(RecommendationCalculator::axisLevel))
                .orElse(null);
        int level = worst == null ? 0 : axisLevel(worst);
        String axisName = worst == null ? "" : worst.axis().displayName().toLowerCase();

        if (level >= 4) {
            return new Recommendation(RecommendationLevel.AVOID,
                    "Security looks clean, but a critical " + axisName + " risk makes this unsafe to run as-is.",
                    perAxis);
        }
        if (level == 3) {
            return new Recommendation(RecommendationLevel.RISKY,
                    "Security looks clean, but there is a high " + axisName + " risk — review before installing.",
                    perAxis);
        }
        if (level == 2) {
            return new Recommendation(RecommendationLevel.INSTALL_WITH_CARE,
                    "No serious issues, but some " + axisName + " concerns — install with care.", perAxis);
        }
        return new Recommendation(RecommendationLevel.SAFE_TO_INSTALL,
                "No significant security or quality concerns were found in static analysis.", perAxis);
    }

    /** Effective severity level of a non-security axis: 4=critical, 3=high, 2=medium, 0=none. */
    private static int axisLevel(AxisScore a) {
        if (a.counts().critical() > 0 || a.verdict() == Verdict.CRITICAL_RISK) return 4;
        if (a.counts().high() > 0 || a.verdict() == Verdict.HIGH_RISK) return 3;
        if (a.counts().medium() > 0 || a.verdict() == Verdict.MEDIUM_RISK) return 2;
        return 0;
    }
}
