package dev.pluginguard.engine.perf;

import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.bytecode.ClassScanner;
import dev.pluginguard.engine.model.ClassFile;
import dev.pluginguard.support.JarBuilder;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class CallGraphTest {

    @Test
    void helperReachableFromHandlerWithIncreasedDistance() {
        // onMove -> Helper.help (intra-jar edge). help is reachable at distance 1.
        List<ClassScan> classes = scanAll(new JarBuilder()
                .addListenerClass("com/x/L", "onMove", "org/bukkit/event/player/PlayerMoveEvent",
                        JarBuilder.calls(new JarBuilder.Call("com/x/Helper", "help")))
                .addClass("com/x/Helper", "help", JarBuilder.calls(
                        new JarBuilder.Call("java/sql/DriverManager", "getConnection")), List.of())
                .build());

        CallGraph graph = new CallGraph(classes);
        Map<String, CallGraph.Reach> reach = graph.reachableFrom(
                List.of(new HotEntrypoint("com/x/L", "onMove", Heat.HOT)), 5);

        assertThat(reach).containsKey(CallGraph.key("com/x/L", "onMove"));
        CallGraph.Reach helper = reach.get(CallGraph.key("com/x/Helper", "help"));
        assertThat(helper).isNotNull();
        assertThat(helper.distance()).isEqualTo(1);
        assertThat(helper.heat()).isEqualTo(Heat.HOT);
    }

    @Test
    void coldMethodNotReachableFromHotEntrypoint() {
        List<ClassScan> classes = scanAll(new JarBuilder()
                .addListenerClass("com/x/L", "onMove", "org/bukkit/event/player/PlayerMoveEvent",
                        JarBuilder.calls())
                .addClass("com/x/Plugin", "onEnable", JarBuilder.calls(
                        new JarBuilder.Call("java/sql/DriverManager", "getConnection")), List.of())
                .build());

        CallGraph graph = new CallGraph(classes);
        Map<String, CallGraph.Reach> reach = graph.reachableFrom(
                List.of(new HotEntrypoint("com/x/L", "onMove", Heat.HOT)), 5);

        assertThat(reach).doesNotContainKey(CallGraph.key("com/x/Plugin", "onEnable"));
    }

    @Test
    void recursionTerminates() {
        // self-recursive method must not loop forever.
        List<ClassScan> classes = scanAll(new JarBuilder()
                .addClass("com/x/R", "loop", JarBuilder.calls(new JarBuilder.Call("com/x/R", "loop")), List.of())
                .build());
        CallGraph graph = new CallGraph(classes);
        Map<String, CallGraph.Reach> reach = graph.reachableFrom(
                List.of(new HotEntrypoint("com/x/R", "loop", Heat.WARM)), 5);
        assertThat(reach).containsKey(CallGraph.key("com/x/R", "loop"));
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
