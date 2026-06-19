package dev.pluginguard.scoring;

import dev.pluginguard.engine.model.Axis;
import dev.pluginguard.engine.model.AxisScore;
import dev.pluginguard.engine.model.Recommendation;
import dev.pluginguard.engine.model.RecommendationLevel;
import dev.pluginguard.engine.model.Verdict;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
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

        // Worst non-security axis drives the rest.
        AxisScore worst = axes.stream()
                .filter(a -> a.axis() != Axis.SECURITY)
                .max((x, y) -> Integer.compare(x.verdict().ordinal(), y.verdict().ordinal()))
                .orElse(null);
        Verdict other = worst == null ? Verdict.MINIMAL_RISK : worst.verdict();
        String axisName = worst == null ? "" : worst.axis().displayName().toLowerCase();

        if (other == Verdict.CRITICAL_RISK) {
            return new Recommendation(RecommendationLevel.AVOID,
                    "Security looks clean, but a critical " + axisName + " risk makes this unsafe to run as-is.",
                    perAxis);
        }
        if (other == Verdict.HIGH_RISK) {
            return new Recommendation(RecommendationLevel.RISKY,
                    "Security looks clean, but there is a high " + axisName + " risk — review before installing.",
                    perAxis);
        }
        if (other == Verdict.MEDIUM_RISK) {
            return new Recommendation(RecommendationLevel.INSTALL_WITH_CARE,
                    "No serious issues, but some " + axisName + " concerns — install with care.", perAxis);
        }
        return new Recommendation(RecommendationLevel.SAFE_TO_INSTALL,
                "No significant security or quality concerns were found in static analysis.", perAxis);
    }
}
