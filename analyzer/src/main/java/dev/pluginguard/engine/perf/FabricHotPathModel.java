package dev.pluginguard.engine.perf;

import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.model.ArtifactType;
import java.util.List;

public class FabricHotPathModel implements HotPathModel {
    @Override public boolean supports(ArtifactType t) {
        return t == ArtifactType.MOD_FABRIC || t == ArtifactType.MOD_QUILT;
    }
    @Override public List<HotEntrypoint> entrypoints(List<ClassScan> classes) { return List.of(); }
}
