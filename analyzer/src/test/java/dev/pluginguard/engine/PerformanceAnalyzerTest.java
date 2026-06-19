package dev.pluginguard.engine;

import dev.pluginguard.engine.model.Axis;
import dev.pluginguard.engine.model.Category;
import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.ScanResult;
import dev.pluginguard.engine.model.Severity;
import dev.pluginguard.support.JarBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class PerformanceAnalyzerTest {

    @Autowired
    AnalysisEngine engine;

    private static byte[] pluginYml(JarBuilder b, String main) {
        return b.addResource("plugin.yml",
                "name: T\nversion: 1.0\nmain: " + main + "\napi-version: 1.21\n").build();
    }

    @Test
    void jdbcInPlayerMoveIsCriticalPerformanceFinding() {
        byte[] jar = pluginYml(new JarBuilder()
                .addClass("com/x/Plugin")
                .addListenerClass("com/x/L", "onMove", "org/bukkit/event/player/PlayerMoveEvent",
                        JarBuilder.calls(new JarBuilder.Call("java/sql/DriverManager", "getConnection"))),
                "com.x.Plugin");

        ScanResult result = engine.analyze("p1", "t.jar", jar);

        Finding perf = result.findings().stream()
                .filter(f -> f.category() == Category.PERFORMANCE).findFirst().orElse(null);
        assertThat(perf).isNotNull();
        assertThat(perf.severity()).isEqualTo(Severity.CRITICAL);
        assertThat(result.axes()).anyMatch(a -> a.axis() == Axis.PERFORMANCE);
    }

    @Test
    void jdbcInOnEnableIsNotAPerformanceFinding() {
        byte[] jar = pluginYml(new JarBuilder()
                .addClass("com/x/Plugin", "onEnable",
                        JarBuilder.calls(new JarBuilder.Call("java/sql/DriverManager", "getConnection")), List.of()),
                "com.x.Plugin");

        ScanResult result = engine.analyze("p2", "t.jar", jar);

        assertThat(result.findings()).noneMatch(f -> f.category() == Category.PERFORMANCE);
    }

    @Test
    void asyncWrappedJdbcIsNotFlagged() {
        // A BukkitRunnable subclass with JDBC in run(), but registered ONLY via async scheduler.
        byte[] jar = pluginYml(new JarBuilder()
                .addRunnableClass("com/x/Task",
                        JarBuilder.calls(new JarBuilder.Call("java/sql/DriverManager", "getConnection")))
                .addClass("com/x/Plugin", "onEnable",
                        JarBuilder.calls(new JarBuilder.Call(
                                "org/bukkit/scheduler/BukkitRunnable", "runTaskTimerAsynchronously")), List.of()),
                "com.x.Plugin");

        ScanResult result = engine.analyze("p3", "t.jar", jar);

        assertThat(result.findings()).noneMatch(f -> f.category() == Category.PERFORMANCE);
    }

    @Test
    void benignPluginHasNoPerformanceFindings() {
        byte[] jar = pluginYml(new JarBuilder()
                .addClass("com/x/Plugin")
                .addListenerClass("com/x/L", "onJoin", "org/bukkit/event/player/PlayerJoinEvent",
                        JarBuilder.calls()),
                "com.x.Plugin");

        ScanResult result = engine.analyze("p4", "t.jar", jar);
        assertThat(result.findings()).noneMatch(f -> f.category() == Category.PERFORMANCE);
    }
}
