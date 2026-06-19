package dev.pluginguard.engine.bytecode;

import dev.pluginguard.engine.model.ClassFile;
import dev.pluginguard.support.JarBuilder;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class MethodAnnotationCaptureTest {

    @Test
    void eventHandlerAnnotationIsCaptured() {
        byte[] jar = new JarBuilder()
                .addListenerClass("com/x/L", "onMove",
                        "org/bukkit/event/player/PlayerMoveEvent", JarBuilder.calls())
                .build();
        ClassScan scan = scan(jar, "com/x/L.class", "com/x/L");

        MethodInfo handler = scan.methods().stream()
                .filter(m -> m.name().equals("onMove")).findFirst().orElseThrow();
        assertThat(handler.annotations()).contains("Lorg/bukkit/event/EventHandler;");
    }

    private static ClassScan scan(byte[] jar, String entry, String name) {
        try (var zis = new java.util.zip.ZipInputStream(new java.io.ByteArrayInputStream(jar))) {
            java.util.zip.ZipEntry e;
            while ((e = zis.getNextEntry()) != null) {
                if (e.getName().equals(entry)) {
                    return ClassScanner.scan(new ClassFile(name, zis.readAllBytes(), ""));
                }
            }
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
        throw new IllegalStateException("missing " + entry);
    }
}
