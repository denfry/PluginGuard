package dev.pluginguard.api;

import dev.pluginguard.engine.model.ArtifactType;
import dev.pluginguard.engine.model.ScanResult;
import dev.pluginguard.engine.model.SeverityCounts;
import dev.pluginguard.engine.model.Verdict;

/**
 * One entry in a bulk-scan response: a compact summary of a scanned artifact, or an {@code error}
 * for a file that could not be scanned (unsupported type, unreadable). Full reports stay fetchable
 * by {@code id} via {@code GET /api/scan/{id}}.
 */
public record BatchScanItem(
        String fileName,
        String id,
        Integer score,
        Verdict verdict,
        ArtifactType artifactType,
        SeverityCounts counts,
        String error) {

    static BatchScanItem ok(ScanResult r) {
        return new BatchScanItem(r.fileName(), r.id(), r.score(), r.verdict(), r.artifactType(), r.counts(), null);
    }

    static BatchScanItem failed(String fileName, String error) {
        return new BatchScanItem(fileName, null, null, null, null, null, error);
    }
}
