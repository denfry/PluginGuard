package dev.pluginguard.scoring;

import dev.pluginguard.engine.model.Axis;
import dev.pluginguard.engine.model.AxisScore;
import dev.pluginguard.engine.model.Recommendation;
import dev.pluginguard.engine.model.RecommendationLevel;
import dev.pluginguard.engine.model.SeverityCounts;
import dev.pluginguard.engine.model.Verdict;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class RecommendationCalculatorTest {

    private final RecommendationCalculator calc = new RecommendationCalculator();

    private static AxisScore axis(Axis a, Verdict v) {
        return new AxisScore(a, 50, v, new SeverityCounts(0, 0, 0, 0, 0), "x");
    }

    @Test
    void securityCriticalVetoesEverything() {
        Recommendation r = calc.recommend(List.of(
                axis(Axis.SECURITY, Verdict.CRITICAL_RISK),
                axis(Axis.PERFORMANCE, Verdict.MINIMAL_RISK)));
        assertThat(r.level()).isEqualTo(RecommendationLevel.DO_NOT_INSTALL);
    }

    @Test
    void securityHighIsAvoid() {
        Recommendation r = calc.recommend(List.of(axis(Axis.SECURITY, Verdict.HIGH_RISK)));
        assertThat(r.level()).isEqualTo(RecommendationLevel.AVOID);
    }

    @Test
    void performanceCriticalWithCleanSecurityIsAvoid() {
        Recommendation r = calc.recommend(List.of(
                axis(Axis.SECURITY, Verdict.MINIMAL_RISK),
                axis(Axis.PERFORMANCE, Verdict.CRITICAL_RISK)));
        assertThat(r.level()).isEqualTo(RecommendationLevel.AVOID);
        assertThat(r.headline().toLowerCase()).contains("performance");
    }

    @Test
    void allCleanIsSafeToInstall() {
        Recommendation r = calc.recommend(List.of(
                axis(Axis.SECURITY, Verdict.MINIMAL_RISK),
                axis(Axis.PERFORMANCE, Verdict.LOW_RISK)));
        assertThat(r.level()).isEqualTo(RecommendationLevel.SAFE_TO_INSTALL);
    }

    @Test
    void nonSecurityMediumIsInstallWithCare() {
        Recommendation r = calc.recommend(List.of(
                axis(Axis.SECURITY, Verdict.MINIMAL_RISK),
                axis(Axis.PERFORMANCE, Verdict.MEDIUM_RISK)));
        assertThat(r.level()).isEqualTo(RecommendationLevel.INSTALL_WITH_CARE);
    }
}
