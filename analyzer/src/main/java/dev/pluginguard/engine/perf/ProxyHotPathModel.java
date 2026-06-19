package dev.pluginguard.engine.perf;

import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.model.ArtifactType;
import java.util.List;

public class ProxyHotPathModel implements HotPathModel {
    @Override public boolean supports(ArtifactType t) {
        return t == ArtifactType.PLUGIN_BUNGEE || t == ArtifactType.PLUGIN_VELOCITY;
    }
    @Override public List<HotEntrypoint> entrypoints(List<ClassScan> classes) { return List.of(); }
}
