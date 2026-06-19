package dev.pluginguard.engine.perf;

import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.model.ArtifactType;

import java.util.List;

/** Artifact-family-specific detection of "hot path" entrypoints. */
public interface HotPathModel {

    boolean supports(ArtifactType type);

    List<HotEntrypoint> entrypoints(List<ClassScan> classes);
}
