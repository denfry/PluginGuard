package dev.pluginguard.support;

import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.bytecode.ClassScanner;
import dev.pluginguard.engine.model.ClassFile;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class JarBuilderPerfScaffoldTest {

    @Test
    void listenerClassHasInterfaceAndInvokesItsCalls() {
        byte[] jar = new JarBuilder()
                .addListenerClass("com/x/Listener", "onMove",
                        "org/bukkit/event/player/PlayerMoveEvent",
                        JarBuilder.calls(new JarBuilder.Call("com/x/Helper", "help")))
                .build();
        // Pull the class bytes back out and scan them.
        ClassScan scan = scanFromJar(jar, "com/x/Listener.class", "com/x/Listener");

        assertThat(scan.interfaces()).contains("org/bukkit/event/Listener");
        assertThat(scan.methods()).anyMatch(m -> m.name().equals("onMove"));
        assertThat(scan.invocations()).anyMatch(i ->
                i.owner().equals("com/x/Helper") && i.name().equals("help")
                        && i.callerMethod().equals("onMove"));
    }

    @Test
    void runnableClassExtendsBukkitRunnable() {
        byte[] jar = new JarBuilder()
                .addRunnableClass("com/x/Task",
                        JarBuilder.calls(new JarBuilder.Call("java/sql/DriverManager", "getConnection")))
                .build();
        ClassScan scan = scanFromJar(jar, "com/x/Task.class", "com/x/Task");
        assertThat(scan.superName()).isEqualTo("org/bukkit/scheduler/BukkitRunnable");
        assertThat(scan.invocations()).anyMatch(i -> i.owner().equals("java/sql/DriverManager"));
    }

    private static ClassScan scanFromJar(byte[] jar, String entry, String internalName) {
        try (var zis = new java.util.zip.ZipInputStream(new java.io.ByteArrayInputStream(jar))) {
            java.util.zip.ZipEntry e;
            while ((e = zis.getNextEntry()) != null) {
                if (e.getName().equals(entry)) {
                    return ClassScanner.scan(new ClassFile(internalName, zis.readAllBytes(), ""));
                }
            }
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
        throw new IllegalStateException("entry not found: " + entry);
    }
}
