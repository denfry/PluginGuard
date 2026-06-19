package dev.pluginguard.engine;

import dev.pluginguard.engine.model.Axis;
import dev.pluginguard.engine.model.ScanResult;
import dev.pluginguard.support.JarBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class MultiAxisEngineTest {

    @Autowired
    AnalysisEngine engine;

    @Test
    void everyReportHasASecurityAxisAndARecommendation() {
        byte[] jar = new JarBuilder().addClass("com/x/Plugin").build();
        ScanResult result = engine.analyze("ma1", "x.jar", jar);

        assertThat(result.axes()).isNotNull();
        assertThat(result.axes()).anyMatch(a -> a.axis() == Axis.SECURITY);
        assertThat(result.recommendation()).isNotNull();
        // Top-level score equals the SECURITY axis score (backward compatibility).
        int securityScore = result.axes().stream()
                .filter(a -> a.axis() == Axis.SECURITY).findFirst().orElseThrow().score();
        assertThat(result.score()).isEqualTo(securityScore);
    }
}
