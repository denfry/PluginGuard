package dev.pluginguard.api;

import dev.pluginguard.api.auth.ApiPrincipal;
import dev.pluginguard.engine.AnalysisEngine;
import dev.pluginguard.engine.AnalysisException;
import dev.pluginguard.engine.model.ScanResult;
import dev.pluginguard.engine.sandbox.SandboxService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/** REST API for the PluginGuard analyzer. */
@RestController
@RequestMapping("/api")
public class ScanController {

    private final AnalysisEngine engine;
    private final ScanStore store;
    private final SandboxService sandbox;

    public ScanController(AnalysisEngine engine, ScanStore store, SandboxService sandbox) {
        this.engine = engine;
        this.store = store;
        this.sandbox = sandbox;
    }

    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", "ok", "engine", AnalysisEngine.ENGINE_VERSION);
    }

    /** Uploads a plugin JAR and returns its security report synchronously (static analysis is fast). */
    @PostMapping("/scan")
    public ResponseEntity<ScanResult> scan(@RequestParam("file") MultipartFile file, HttpServletRequest request) {
        return ResponseEntity.ok(scanOne(file, sandboxEntitled(request)));
    }

    /**
     * Bulk scan: upload several artifacts in one request (multipart {@code files}). Each is scanned
     * independently — a file that fails (unsupported type, unreadable) becomes an error entry rather
     * than failing the whole batch. Returns compact summaries; full reports are fetchable by id.
     *
     * <p>Bulk scanning is a keyed feature: under the API layer it requires a (non-anonymous) key.
     * The batch currently counts as a single metered call — per-file metering is a follow-up.
     */
    @PostMapping("/scan/batch")
    public List<BatchScanItem> scanBatch(@RequestParam("files") List<MultipartFile> files,
                                         HttpServletRequest request) {
        requireBulkAccess(request);
        if (files == null || files.isEmpty()) {
            throw new AnalysisException("No files were uploaded.");
        }
        if (files.size() > MAX_BATCH_FILES) {
            throw new AnalysisException("Too many files in one batch (max " + MAX_BATCH_FILES + ").");
        }
        boolean entitled = sandboxEntitled(request);
        List<BatchScanItem> items = new ArrayList<>(files.size());
        for (MultipartFile file : files) {
            try {
                items.add(BatchScanItem.ok(scanOne(file, entitled)));
            } catch (AnalysisException e) {
                items.add(BatchScanItem.failed(sanitizeFileName(file.getOriginalFilename()), e.getMessage()));
            }
        }
        return items;
    }

    /** Validates, analyzes, attaches the sandbox section, stores and returns one report. */
    private ScanResult scanOne(MultipartFile file, boolean sandboxEntitled) {
        if (file == null || file.isEmpty()) {
            throw new AnalysisException("No file was uploaded.");
        }
        String fileName = sanitizeFileName(file.getOriginalFilename());
        if (!isSupportedExtension(fileName)) {
            throw new AnalysisException("Unsupported file type. Upload a plugin/mod .jar, or a resource/data "
                    + "pack .zip (.mcpack/.litemod also accepted).");
        }
        byte[] data;
        try {
            data = file.getBytes();
        } catch (IOException e) {
            throw new AnalysisException("Could not read the uploaded file.", e);
        }
        String id = UUID.randomUUID().toString();
        ScanResult result = engine.analyze(id, fileName, data);
        // Attach the (optional) dynamic sandbox section and, if enabled and the caller is entitled,
        // launch the async run. The static report is returned immediately; GET /api/scan/{id}
        // reflects the sandbox status.
        result = sandbox.attach(result, data, sandboxEntitled);
        store.put(result);
        return result;
    }

    /** Bulk scanning is a keyed feature: under the API layer it requires a (non-anonymous) key. */
    private static void requireBulkAccess(HttpServletRequest request) {
        Object attr = request.getAttribute(ApiPrincipal.REQUEST_ATTRIBUTE);
        if (attr instanceof ApiPrincipal principal && principal.anonymous()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Bulk scanning requires an API key.");
        }
    }

    /**
     * Whether the caller's plan includes the dynamic sandbox. With no API layer (default in-memory
     * profile) there is no principal, so the global sandbox setting governs as before. Under the
     * {@code postgres} profile only Pro/Business keys are entitled; the free/anonymous tier gets
     * static analysis only.
     */
    private static boolean sandboxEntitled(HttpServletRequest request) {
        Object attr = request.getAttribute(ApiPrincipal.REQUEST_ATTRIBUTE);
        if (!(attr instanceof ApiPrincipal principal)) {
            return true;
        }
        return !principal.anonymous() && principal.plan() != null && principal.plan().dynamicSandbox();
    }

    @GetMapping("/scan/{id}")
    public ScanResult report(@PathVariable String id) {
        if ("demo".equals(id)) {
            return DemoData.sample();
        }
        return store.get(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Report not found"));
    }

    @GetMapping("/demo")
    public ScanResult demo() {
        return DemoData.sample();
    }

    /** Plugins/mods ship as {@code .jar}; resource/data packs as {@code .zip} ({@code .mcpack}/{@code .litemod} too). */
    private static final Set<String> SUPPORTED_EXTENSIONS = Set.of(".jar", ".zip", ".mcpack", ".litemod");

    /** Upper bound on files accepted in one {@code /api/scan/batch} request. */
    private static final int MAX_BATCH_FILES = 50;

    private static boolean isSupportedExtension(String fileName) {
        String lower = fileName.toLowerCase(Locale.ROOT);
        return SUPPORTED_EXTENSIONS.stream().anyMatch(lower::endsWith);
    }

    private static String sanitizeFileName(String name) {
        if (name == null || name.isBlank()) {
            return "upload.jar";
        }
        // Strip any path components a client might include.
        String base = name.replace('\\', '/');
        base = base.substring(base.lastIndexOf('/') + 1);
        return base;
    }
}
