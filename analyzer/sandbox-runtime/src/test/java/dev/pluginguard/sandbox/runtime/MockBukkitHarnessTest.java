package dev.pluginguard.sandbox.runtime;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end exercise of the in-container harness, in-process: it packages a synthetic plugin into a
 * jar, drives it through the mock Bukkit lifecycle, and asserts the behavior log captured both the
 * lifecycle trail and the instrumented reflective call inside {@code onEnable}.
 */
class MockBukkitHarnessTest {

    private static final String PLUGIN_YML = """
            name: Demo
            version: "1.0"
            main: demo.DemoPlugin
            api-version: "1.21"
            commands:
              demo:
                description: a demo command
            """;

    @Test
    void drivesPluginLifecycleAndCapturesInstrumentedBehavior(@TempDir Path dir) throws Exception {
        Path jar = dir.resolve("demo-plugin.jar");
        buildPluginJar(jar);
        Path log = dir.resolve("behavior.jsonl");

        BehaviorLog result = MockBukkitHarness.run(jar, log, "demo.DemoPlugin", List.of("demo"));
        List<BehaviorEvent> events = result.events();

        assertTrue(has(events, "LIFECYCLE", "onEnable"), "onEnable lifecycle missing: " + events);
        assertTrue(has(events, "LIFECYCLE", "onCommand:demo"), "onCommand lifecycle missing: " + events);

        // The reflective call inside onEnable was instrumented and recorded.
        assertTrue(events.stream().anyMatch(e ->
                        "REFLECTION".equals(e.type()) && e.target() != null && e.target().contains("java.lang.Class.forName")),
                "expected instrumented REFLECTION event, got: " + events);

        // The command's sendMessage produced output.
        assertTrue(events.stream().anyMatch(e ->
                        "OUTPUT".equals(e.type()) && e.detail() != null && e.detail().contains("demo ran demo")),
                "expected OUTPUT from onCommand, got: " + events);

        // The structured log was also persisted to disk for the orchestrator to read back.
        assertTrue(Files.exists(log), "behavior log file should exist");
        assertTrue(Files.readString(log).contains("\"REFLECTION\""), "log file should contain the events");
    }

    private static boolean has(List<BehaviorEvent> events, String type, String target) {
        return events.stream().anyMatch(e -> type.equals(e.type()) && target.equals(e.target()));
    }

    private static void buildPluginJar(Path jar) throws Exception {
        byte[] pluginClass;
        try (InputStream in = MockBukkitHarnessTest.class.getClassLoader()
                .getResourceAsStream("demo/DemoPlugin.class")) {
            assertNotNull(in, "compiled DemoPlugin.class on the test classpath");
            pluginClass = in.readAllBytes();
        }
        try (ZipOutputStream zos = new ZipOutputStream(Files.newOutputStream(jar))) {
            putEntry(zos, "plugin.yml", PLUGIN_YML.getBytes(StandardCharsets.UTF_8));
            putEntry(zos, "demo/DemoPlugin.class", pluginClass);
        }
    }

    private static void putEntry(ZipOutputStream zos, String name, byte[] bytes) throws Exception {
        zos.putNextEntry(new ZipEntry(name));
        zos.write(bytes);
        zos.closeEntry();
    }
}
