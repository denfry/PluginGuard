package dev.pluginguard.scoring;

import dev.pluginguard.engine.model.Axis;
import dev.pluginguard.engine.model.AxisScore;
import dev.pluginguard.engine.model.Category;
import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.Severity;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ScoreByAxisTest {

    private final ScoreCalculator calc = new ScoreCalculator();

    private static Finding f(Category cat, Severity sev, String ruleId, int impact) {
        return Finding.builder(ruleId, cat, sev).title(ruleId).scoreImpact(impact).build();
    }

    @Test
    void securityAxisScoreEqualsLegacyScoreWhenOnlySecurityFindings() {
        List<Finding> findings = List.of(
                f(Category.NETWORK, Severity.LOW, "A", 8),
                f(Category.REFLECTION, Severity.MEDIUM, "B", 6));

        int legacy = calc.score(findings);
        List<AxisScore> axes = calc.scoreByAxis(findings);

        AxisScore security = axes.stream().filter(a -> a.axis() == Axis.SECURITY).findFirst().orElseThrow();
        assertThat(security.score()).isEqualTo(legacy);
        assertThat(axes).extracting(AxisScore::axis).containsExactly(Axis.SECURITY); // no perf findings
    }

    @Test
    void axesAreScoredIndependently() {
        List<Finding> findings = List.of(
                f(Category.NETWORK, Severity.LOW, "SEC", 5),
                f(Category.PERFORMANCE, Severity.CRITICAL, "PERF", 35));

        List<AxisScore> axes = calc.scoreByAxis(findings);

        AxisScore security = axes.stream().filter(a -> a.axis() == Axis.SECURITY).findFirst().orElseThrow();
        AxisScore perf = axes.stream().filter(a -> a.axis() == Axis.PERFORMANCE).findFirst().orElseThrow();
        // The perf-critical does NOT drag the security score down.
        assertThat(security.score()).isEqualTo(95);
        assertThat(perf.score()).isLessThanOrEqualTo(15);
        assertThat(perf.verdict().name()).isEqualTo("CRITICAL_RISK");
    }

    @Test
    void axisWithNoFindingsIsOmitted() {
        List<AxisScore> axes = calc.scoreByAxis(List.of(f(Category.NETWORK, Severity.LOW, "A", 5)));
        assertThat(axes).extracting(AxisScore::axis).containsExactly(Axis.SECURITY);
    }
}
