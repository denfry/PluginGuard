package dev.pluginguard.engine.sandbox;

import dev.pluginguard.api.ScanStore;
import dev.pluginguard.config.AnalyzerProperties;
import dev.pluginguard.engine.model.BehaviorEvent;
import dev.pluginguard.engine.model.DynamicFinding;
import dev.pluginguard.engine.model.SandboxReport;
import dev.pluginguard.engine.model.SandboxStatus;
import dev.pluginguard.engine.model.ScanResult;
import dev.pluginguard.engine.model.Severity;
import dev.pluginguard.engine.model.Verdict;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Orchestrates the optional Phase&nbsp;3 dynamic sandbox. The static report is returned immediately;
 * when the sandbox is enabled and the plugin can be driven, the run happens asynchronously and the
 * stored report is updated in place (so {@code GET /api/scan/{id}} reflects PENDING → RUNNING →
 * COMPLETED). Dynamic CRITICAL/HIGH behavior floors the verdict, since it is evidence the code
 * <em>actually ran</em> the action.
 */
@Service
public class SandboxService {

    private static final Logger log = LoggerFactory.getLogger(SandboxService.class);

    private final AnalyzerProperties.Sandbox cfg;
    private final SandboxRunner runner;
    private final DynamicFindingMapper mapper = new DynamicFindingMapper();
    private final ScanStore store;
    private final ExecutorService executor = Executors.newFixedThreadPool(2, r -> {
        Thread t = new Thread(r, "sandbox-worker");
        t.setDaemon(true);
        return t;
    });

    public SandboxService(AnalyzerProperties properties, SandboxRunner runner, ScanStore store) {
        this.cfg = properties.getSandbox();
        this.runner = runner;
        this.store = store;
    }

    /** Entitled by default — preserves behavior for callers without a plan (default profile). */
    public ScanResult attach(ScanResult result, byte[] jarBytes) {
        return attach(result, jarBytes, true);
    }

    /**
     * Attaches the initial sandbox section to a freshly produced static report and, if a run is
     * warranted, launches it asynchronously. Returns immediately.
     *
     * @param sandboxEntitled whether the caller's plan includes dynamic analysis. When {@code false}
     *                        (e.g. the free tier) the run is skipped even if the sandbox is globally
     *                        enabled — the dynamic sandbox is a paid feature.
     */
    public ScanResult attach(ScanResult result, byte[] jarBytes, boolean sandboxEntitled) {
        if (!cfg.isEnabled()) {
            return result.withSandbox(
                    SandboxReport.of(SandboxStatus.DISABLED, "Dynamic sandbox is disabled.", List.of()),
                    result.verdict(), result.notes());
        }
        if (!sandboxEntitled) {
            return result.withSandbox(
                    SandboxReport.of(SandboxStatus.SKIPPED,
                            "Dynamic analysis is available on the Pro and Business plans.", mapper.caveats()),
                    result.verdict(), result.notes());
        }
        if (result.mainClass() == null || result.mainClass().isBlank()) {
            return result.withSandbox(
                    SandboxReport.of(SandboxStatus.SKIPPED,
                            "No plugin main class to drive; dynamic analysis skipped.", mapper.caveats()),
                    result.verdict(), result.notes());
        }
        ScanResult pending = result.withSandbox(
                SandboxReport.of(SandboxStatus.PENDING, "Dynamic analysis queued.", mapper.caveats()),
                result.verdict(), result.notes());
        launchAsync(pending, jarBytes);
        return pending;
    }

    private void launchAsync(ScanResult pending, byte[] jarBytes) {
        executor.submit(() -> {
            try {
                store.put(markRunning(pending));
                ScanResult done = execute(pending, jarBytes);
                store.put(done);
            } catch (RuntimeException e) {
                log.warn("Sandbox job {} crashed: {}", pending.id(), e.toString());
                store.put(pending.withSandbox(
                        SandboxReport.of(SandboxStatus.FAILED, "Sandbox job crashed: " + e.getMessage(),
                                mapper.caveats()),
                        pending.verdict(), pending.notes()));
            }
        });
    }

    private ScanResult markRunning(ScanResult pending) {
        return pending.withSandbox(
                SandboxReport.of(SandboxStatus.RUNNING, "Running the plugin in the sandbox…", mapper.caveats()),
                pending.verdict(), pending.notes());
    }

    /**
     * Synchronous core: runs the sandbox and folds the result into the report. Exposed (package
     * visibility) so tests can drive it with a stubbed {@link SandboxRunner}.
     */
    ScanResult execute(ScanResult result, byte[] jarBytes) {
        List<String> commands = result.pluginInfo() != null ? result.pluginInfo().commands() : List.of();
        SandboxJob job = new SandboxJob(result.id(), jarBytes, result.fileName(), result.mainClass(), commands);

        Instant started = Instant.now();
        SandboxOutcome outcome = runner.run(job);
        Instant finished = Instant.now();

        List<BehaviorEvent> events = outcome.events() == null ? List.of() : outcome.events();
        List<DynamicFinding> dynamic = mapper.map(events, result.findings());
        Severity worst = mapper.worstSeverity(dynamic);

        List<BehaviorEvent> trail = events.size() > cfg.getMaxBehaviorEvents()
                ? events.subList(0, cfg.getMaxBehaviorEvents())
                : events;

        SandboxReport report = new SandboxReport(
                outcome.status(),
                runner.name(),
                started,
                finished,
                Duration.between(started, finished).toMillis(),
                worst,
                events.size(),
                dynamic,
                List.copyOf(trail),
                mapper.caveats(),
                outcome.note());

        Verdict verdict = floorVerdict(result.verdict(), worst, outcome.status());
        List<String> notes = withSandboxNote(result.notes(), report, verdict, result.verdict());
        return result.withSandbox(report, verdict, notes);
    }

    /** Dynamic evidence raises (never lowers) the verdict. */
    static Verdict floorVerdict(Verdict staticVerdict, Severity worstDynamic, SandboxStatus status) {
        if (status != SandboxStatus.COMPLETED || worstDynamic == null) {
            return staticVerdict;
        }
        Verdict floor = switch (worstDynamic) {
            case CRITICAL -> Verdict.CRITICAL_RISK;
            case HIGH -> Verdict.HIGH_RISK;
            case MEDIUM -> Verdict.MEDIUM_RISK;
            default -> staticVerdict;
        };
        return floor.ordinal() > staticVerdict.ordinal() ? floor : staticVerdict;
    }

    private static List<String> withSandboxNote(List<String> notes, SandboxReport report,
                                                Verdict newVerdict, Verdict oldVerdict) {
        List<String> out = new ArrayList<>(notes);
        if (report.status() == SandboxStatus.COMPLETED) {
            out.add("Dynamic sandbox observed " + report.behaviorEventCount() + " behavior event(s); "
                    + report.dynamicFindings().size() + " dynamic finding(s).");
            if (newVerdict != oldVerdict) {
                out.add("Verdict raised to " + newVerdict.getLabel() + " by dynamic sandbox evidence.");
            }
        } else if (report.note() != null) {
            out.add("Dynamic sandbox: " + report.note());
        }
        return out;
    }

    @PreDestroy
    void shutdown() {
        executor.shutdownNow();
    }
}
