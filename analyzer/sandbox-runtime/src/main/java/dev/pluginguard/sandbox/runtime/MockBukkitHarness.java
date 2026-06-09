package dev.pluginguard.sandbox.runtime;

import org.bukkit.Bukkit;
import org.bukkit.Server;
import org.bukkit.command.Command;
import org.bukkit.command.CommandSender;
import org.bukkit.plugin.java.JavaPlugin;

import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Entry point that runs <em>inside</em> the isolated container. It loads the uploaded plugin through
 * an {@link InstrumentingClassLoader}, wires a {@link MockServer}, and drives the plugin's real
 * lifecycle ({@code onLoad} → {@code onEnable} → declared commands → {@code onDisable}). Everything
 * the plugin does is captured to the structured behavior log for the analyzer to read back.
 *
 * <p>Usage: {@code java -javaagent:runtime.jar -jar runtime.jar <plugin.jar> <log.jsonl> [mainClass] [cmd...]}
 */
public final class MockBukkitHarness {

    private MockBukkitHarness() {
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            System.err.println("usage: <plugin.jar> <log.jsonl> [mainClass] [command...]");
            System.exit(2);
            return;
        }
        Path pluginJar = Path.of(args[0]);
        Path logPath = Path.of(args[1]);
        String mainClass = args.length > 2 && !args[2].isBlank() ? args[2] : null;
        List<String> commands = new ArrayList<>();
        for (int i = 3; i < args.length; i++) {
            commands.add(args[i]);
        }
        BehaviorLog log = run(pluginJar, logPath, mainClass, commands);
        log.close();
        // Exit explicitly so a plugin's lingering non-daemon threads do not hold the JVM open.
        Runtime.getRuntime().halt(0);
    }

    /**
     * Drives the plugin and returns the behavior log (also written to {@code logPath}). The log's
     * in-memory copy lets in-process tests assert without re-parsing the file.
     */
    public static BehaviorLog run(Path pluginJar, Path logPath, String mainClassName, List<String> commands) {
        BehaviorLog log = BehaviorLog.toFile(logPath);
        SandboxGuard.install(log);
        SandboxGuard.lifecycle("sandboxStart", pluginJar.getFileName().toString());

        InstrumentingClassLoader loader = null;
        try {
            String main = mainClassName != null ? mainClassName : readMainClass(pluginJar);
            if (main == null) {
                SandboxGuard.record("ERROR", "mainClass", "could not determine plugin main class", null, false);
                return log;
            }
            loader = new InstrumentingClassLoader(pluginJar, MockBukkitHarness.class.getClassLoader());
            SandboxGuard.setPluginLoader(loader);

            Class<?> type = Class.forName(main, false, loader);
            Object instance = type.getDeclaredConstructor().newInstance();
            if (instance instanceof JavaPlugin plugin) {
                drive(plugin, main, commands, dataFolderFor(logPath));
            } else {
                SandboxGuard.record("ERROR", main, "main class does not extend JavaPlugin", null, false);
            }
        } catch (Throwable t) {
            SandboxGuard.record("ERROR", "harness", t.toString(), null, false);
        } finally {
            SandboxGuard.lifecycle("sandboxEnd", null);
            SandboxGuard.setPluginLoader(null);
        }
        return log;
    }

    /** Runs the lifecycle on an already-constructed plugin (the testable core). */
    public static void drive(JavaPlugin plugin, String mainClass, List<String> commands, File dataFolder) {
        Server server = new MockServer();
        Bukkit.setServer(server);
        plugin.initSandbox(server, dataFolder, simpleName(mainClass));

        step("onLoad", () -> plugin.onLoad());
        plugin.setEnabled(true);
        step("onEnable", () -> plugin.onEnable());

        CommandSender console = server.getConsoleSender();
        for (String cmd : commands) {
            step("onCommand:" + cmd, () ->
                    plugin.onCommand(console, new Command(cmd), cmd, new String[]{"sandbox"}));
        }

        step("onDisable", () -> plugin.onDisable());
        plugin.setEnabled(false);
    }

    private interface Action {
        void run() throws Throwable;
    }

    private static void step(String stage, Action action) {
        SandboxGuard.lifecycle(stage, null);
        try {
            action.run();
        } catch (Throwable t) {
            // A crash in one lifecycle stage must not stop the others; record and continue.
            SandboxGuard.record("ERROR", stage, t.toString(), null, false);
        }
    }

    private static File dataFolderFor(Path logPath) {
        try {
            Path dir = logPath.toAbsolutePath().getParent().resolve("plugin-data");
            Files.createDirectories(dir);
            return dir.toFile();
        } catch (Exception e) {
            return new File(System.getProperty("java.io.tmpdir", "."), "plugin-data");
        }
    }

    /** Reads the {@code main:} class from the plugin's {@code plugin.yml} without a YAML parser. */
    private static String readMainClass(Path pluginJar) {
        try (JarFile jar = new JarFile(pluginJar.toFile())) {
            JarEntry entry = jar.getJarEntry("plugin.yml");
            if (entry == null) {
                return null;
            }
            try (InputStream in = jar.getInputStream(entry)) {
                String text = new String(in.readAllBytes(), StandardCharsets.UTF_8);
                for (String line : text.split("\\R")) {
                    String trimmed = line.trim();
                    if (trimmed.startsWith("main:")) {
                        return trimmed.substring("main:".length()).trim().replace("\"", "").replace("'", "");
                    }
                }
            }
        } catch (Exception e) {
            return null;
        }
        return null;
    }

    private static String simpleName(String fqcn) {
        int dot = fqcn.lastIndexOf('.');
        return dot < 0 ? fqcn : fqcn.substring(dot + 1);
    }
}
