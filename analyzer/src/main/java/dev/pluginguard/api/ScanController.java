package dev.pluginguard.api;

import dev.pluginguard.engine.AnalysisEngine;
import dev.pluginguard.engine.AnalysisException;
import dev.pluginguard.engine.model.ScanResult;
import dev.pluginguard.engine.sandbox.SandboxService;
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
import java.util.Locale;
import java.util.Map;
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
    public ResponseEntity<ScanResult> scan(@RequestParam("file") MultipartFile file) {
        if (file == null || file.isEmpty()) {
            throw new AnalysisException("No file was uploaded.");
        }
        String fileName = sanitizeFileName(file.getOriginalFilename());
        if (!fileName.toLowerCase(Locale.ROOT).endsWith(".jar")) {
            throw new AnalysisException("Only .jar files are supported.");
        }

        byte[] data;
        try {
            data = file.getBytes();
        } catch (IOException e) {
            throw new AnalysisException("Could not read the uploaded file.", e);
        }

        String id = UUID.randomUUID().toString();
        ScanResult result = engine.analyze(id, fileName, data);
        // Attach the (optional) dynamic sandbox section and, if enabled, launch the async run.
        // The static report is returned immediately; GET /api/scan/{id} reflects the sandbox status.
        result = sandbox.attach(result, data);
        store.put(result);
        return ResponseEntity.ok(result);
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
