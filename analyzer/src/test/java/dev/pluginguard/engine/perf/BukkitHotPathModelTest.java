package dev.pluginguard.engine.perf;

import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.bytecode.ClassScanner;
import dev.pluginguard.engine.model.ArtifactType;
import dev.pluginguard.engine.model.ClassFile;
import dev.pluginguard.support.JarBuilder;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class BukkitHotPathModelTest {

    private final BukkitHotPathModel model = new BukkitHotPathModel();

    @Test
    void playerMoveHandlerIsAHotEntrypoint() {
        List<ClassScan> classes = scanAll(new JarBuilder()
                .addListenerClass("com/x/L", "onMove",
                        "org/bukkit/event/player/PlayerMoveEvent", JarBuilder.calls())
                .build());

        List<HotEntrypoint> eps = model.entrypoints(classes);
        assertThat(eps).anyMatch(e ->
                e.classInternalName().equals("com/x/L") && e.methodName().equals("onMove")
                        && e.heat() == Heat.HOT);
    }

    @Test
    void joinHandlerIsCoolNotHot() {
        List<ClassScan> classes = scanAll(new JarBuilder()
                .addListenerClass("com/x/L", "onJoin",
                        "org/bukkit/event/player/PlayerJoinEvent", JarBuilder.calls())
                .build());

        HotEntrypoint ep = model.entrypoints(classes).stream()
                .filter(e -> e.methodName().equals("onJoin")).findFirst().orElseThrow();
        assertThat(ep.heat()).isEqualTo(Heat.COOL);
    }

    @Test
    void supportsBukkitOnly() {
        assertThat(model.supports(ArtifactType.PLUGIN_BUKKIT)).isTrue();
        assertThat(model.supports(ArtifactType.MOD_FABRIC)).isFalse();
    }

    @Test
    void runnableRunIsWarmWhenSyncSchedulerPresent() {
        List<ClassScan> classes = scanAll(new JarBuilder()
                .addRunnableClass("com/x/Task",
                        JarBuilder.calls(new JarBuilder.Call("java/sql/DriverManager", "getConnection")))
                .addClass("com/x/Plugin", "onEnable",
                        JarBuilder.calls(new JarBuilder.Call("org/bukkit/scheduler/BukkitScheduler", "runTaskTimer")),
                        java.util.List.of())
                .build());

        assertThat(model.entrypoints(classes)).anyMatch(e ->
                e.classInternalName().equals("com/x/Task")
                        && e.methodName().equals("run")
                        && e.heat() == Heat.WARM);
    }

    @Test
    void runnableRunIsNotHotWhenOnlyAsyncScheduler() {
        List<ClassScan> classes = scanAll(new JarBuilder()
                .addRunnableClass("com/x/Task",
                        JarBuilder.calls(new JarBuilder.Call("java/sql/DriverManager", "getConnection")))
                .addClass("com/x/Plugin", "onEnable",
                        JarBuilder.calls(new JarBuilder.Call("org/bukkit/scheduler/BukkitScheduler",
                                "runTaskTimerAsynchronously")),
                        java.util.List.of())
                .build());

        assertThat(model.entrypoints(classes)).noneMatch(e -> e.methodName().equals("run"));
    }

    @Test
    void unknownEventDefaultsToWarm() {
        List<ClassScan> classes = scanAll(new JarBuilder()
                .addListenerClass("com/x/L", "onCustom",
                        "com/example/CustomFooEvent", JarBuilder.calls())
                .build());

        assertThat(model.entrypoints(classes)).anyMatch(e ->
                e.methodName().equals("onCustom") && e.heat() == Heat.WARM);
    }

    private static List<ClassScan> scanAll(byte[] jar) {
        List<ClassScan> out = new java.util.ArrayList<>();
        try (var zis = new java.util.zip.ZipInputStream(new java.io.ByteArrayInputStream(jar))) {
            java.util.zip.ZipEntry e;
            while ((e = zis.getNextEntry()) != null) {
                if (e.getName().endsWith(".class")) {
                    String internal = e.getName().substring(0, e.getName().length() - ".class".length());
                    out.add(ClassScanner.scan(new ClassFile(internal, zis.readAllBytes(), "")));
                }
            }
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
        return out;
    }
}
