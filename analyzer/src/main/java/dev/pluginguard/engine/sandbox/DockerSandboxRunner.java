package dev.pluginguard.engine.sandbox;

import dev.pluginguard.config.AnalyzerProperties;
import dev.pluginguard.engine.model.BehaviorEvent;
import dev.pluginguard.engine.model.SandboxStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Runs the plugin inside a hardened, throw-away Docker container: non-root, read-only root
 * filesystem, all capabilities dropped, no new privileges, a pids/cpu/memory cap, and (by default)
 * {@code --network none} so every egress attempt is logged but cannot leave the host. The
 * {@code sandbox-runtime} agent jar is mounted read-only and drives the plugin; the structured
 * behavior log is read back from a writable mount.
 *
 * <p>The command construction is isolated in {@link #buildDockerCommand} so it can be verified
 * without a Docker daemon; the run itself degrades to {@code UNAVAILABLE} when Docker or the agent
 * jar is absent and never throws.
 */
@Component
public class DockerSandboxRunner implements SandboxRunner {

    private static final Logger log = LoggerFactory.getLogger(DockerSandboxRunner.class);

    private final AnalyzerProperties.Sandbox cfg;
    private final BehaviorLogParser parser = new BehaviorLogParser();

    public DockerSandboxRunner(AnalyzerProperties properties) {
        this.cfg = properties.getSandbox();
    }

    @Override
    public String name() {
        return "docker";
    }

    @Override
    public boolean isAvailable() {
        Path jar = runtimeJar();
        if (jar == null || !Files.isRegularFile(jar)) {
            return false;
        }
        try {
            Process p = new ProcessBuilder(cfg.getDockerPath(), "version", "--format", "{{.Server.Version}}")
                    .redirectErrorStream(true).start();
            drain(p.getInputStream());
            return p.waitFor(5, TimeUnit.SECONDS) && p.exitValue() == 0;
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return false;
        }
    }

    @Override
    public SandboxOutcome run(SandboxJob job) {
        Path jar = runtimeJar();
        if (jar == null || !Files.isRegularFile(jar)) {
            return SandboxOutcome.unavailable("Sandbox runtime jar not found (set pluginguard.sandbox.runtime-jar-path).");
        }
        if (!isAvailable()) {
            return SandboxOutcome.unavailable("Docker is not available on the analyzer host.");
        }

        Path runDir = cfg.resolveWorkDir().resolve(job.id());
        Path inDir = runDir.resolve("in");
        Path outDir = runDir.resolve("out");
        try {
            Files.createDirectories(inDir);
            Files.createDirectories(outDir);
            Files.write(inDir.resolve("plugin.jar"), job.jarBytes());
            Files.copy(jar, inDir.resolve("runtime.jar"));
            makeWorldWritable(outDir); // the container's non-root user must be able to write the log

            List<String> cmd = buildDockerCommand(cfg, inDir, outDir, job.mainClass(), job.commands());
            log.info("Sandbox run {} -> {}", job.id(), String.join(" ", cmd));

            boolean timedOut = !exec(cmd, cfg.getTimeoutSeconds() + 10L);
            List<BehaviorEvent> events = readLog(outDir.resolve("behavior.jsonl"));

            if (timedOut) {
                return SandboxOutcome.failed(events, "The sandbox run timed out; results may be partial.");
            }
            return SandboxOutcome.completed(events, null);
        } catch (Exception e) {
            log.warn("Sandbox run {} failed: {}", job.id(), e.toString());
            return new SandboxOutcome(SandboxStatus.FAILED, List.of(), "Sandbox run failed: " + e.getMessage());
        } finally {
            deleteQuietly(runDir);
        }
    }

    /**
     * Builds the hardened {@code docker run} invocation. Pure and side-effect free so it can be
     * asserted in tests without a Docker daemon.
     */
    static List<String> buildDockerCommand(AnalyzerProperties.Sandbox cfg, Path inDir, Path outDir,
                                           String mainClass, List<String> commands) {
        List<String> c = new ArrayList<>();
        c.add(cfg.getDockerPath());
        c.add("run");
        c.add("--rm");
        c.add("--network");
        c.add(cfg.getNetwork());           // "none": no route off the host; attempts are logged
        c.add("--read-only");              // immutable root filesystem
        c.add("--cap-drop");
        c.add("ALL");                      // drop every Linux capability
        c.add("--security-opt");
        c.add("no-new-privileges");        // cannot gain privileges via setuid binaries
        c.add("--pids-limit");
        c.add(String.valueOf(cfg.getPidsLimit()));
        c.add("--memory");
        c.add(cfg.getMemoryMb() + "m");
        c.add("--memory-swap");
        c.add(cfg.getMemoryMb() + "m");    // no swap headroom beyond memory
        c.add("--cpus");
        c.add(cfg.getCpus());
        c.add("-u");
        c.add("65534:65534");              // run as nobody, never root
        c.add("--tmpfs");
        c.add("/tmp:rw,noexec,nosuid,size=64m");
        c.add("-v");
        c.add(inDir.toAbsolutePath() + ":/in:ro");
        c.add("-v");
        c.add(outDir.toAbsolutePath() + ":/out");
        c.add("-w");
        c.add("/in");
        c.add(cfg.getImage());
        // The harness entrypoint, driven through the agent.
        c.add("java");
        c.add("-Djava.security.manager=allow");
        c.add("-XX:-UsePerfData");
        c.add("-javaagent:/in/runtime.jar");
        c.add("-jar");
        c.add("/in/runtime.jar");
        c.add("/in/plugin.jar");
        c.add("/out/behavior.jsonl");
        c.add(mainClass == null ? "" : mainClass);
        if (commands != null) {
            c.addAll(commands);
        }
        return c;
    }

    private Path runtimeJar() {
        String p = cfg.getRuntimeJarPath();
        return p == null || p.isBlank() ? null : Path.of(p);
    }

    private List<BehaviorEvent> readLog(Path logFile) {
        try {
            if (Files.isRegularFile(logFile)) {
                return parser.parse(Files.readString(logFile, StandardCharsets.UTF_8));
            }
        } catch (IOException e) {
            log.warn("Could not read behavior log {}: {}", logFile, e.toString());
        }
        return List.of();
    }

    /** Runs the command, draining output; returns {@code true} if it finished within the timeout. */
    private boolean exec(List<String> cmd, long timeoutSeconds) throws IOException, InterruptedException {
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        drain(p.getInputStream());
        boolean finished = p.waitFor(timeoutSeconds, TimeUnit.SECONDS);
        if (!finished) {
            p.destroyForcibly();
            p.waitFor(5, TimeUnit.SECONDS);
        }
        return finished;
    }

    private static void drain(InputStream in) {
        Thread t = new Thread(() -> {
            try {
                in.readAllBytes();
            } catch (IOException ignored) {
                // process ended
            }
        });
        t.setDaemon(true);
        t.start();
    }

    private static void makeWorldWritable(Path dir) {
        try {
            dir.toFile().setWritable(true, false);
            dir.toFile().setReadable(true, false);
            dir.toFile().setExecutable(true, false);
        } catch (Exception ignored) {
            // best effort; on a Linux host this lets the container's nobody user write the log
        }
    }

    private static void deleteQuietly(Path dir) {
        if (dir == null || !Files.exists(dir)) {
            return;
        }
        try (var paths = Files.walk(dir)) {
            paths.sorted((a, b) -> b.getNameCount() - a.getNameCount())
                    .forEach(p -> {
                        try {
                            Files.deleteIfExists(p);
                        } catch (IOException ignored) {
                            // best effort
                        }
                    });
        } catch (IOException ignored) {
            // best effort
        }
    }
}
