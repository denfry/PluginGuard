package dev.pluginguard.engine.perf;

import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.bytecode.MethodInfo;
import dev.pluginguard.engine.model.ArtifactType;

import java.util.ArrayList;
import java.util.List;

/**
 * Fabric/Quilt hot paths. Fabric tick callbacks are registered as lambdas, not annotated, so we
 * match the conventional functional-interface method names for the per-tick callbacks
 * ({@code ServerTickEvents.EndTick#onEndTick}, {@code StartTick#onStartTick}). Best-effort heuristic.
 */
public class FabricHotPathModel implements HotPathModel {

    private static final List<String> TICK_METHODS = List.of("onEndTick", "onStartTick");

    @Override
    public boolean supports(ArtifactType t) {
        return t == ArtifactType.MOD_FABRIC || t == ArtifactType.MOD_QUILT;
    }

    @Override
    public List<HotEntrypoint> entrypoints(List<ClassScan> classes) {
        List<HotEntrypoint> out = new ArrayList<>();
        for (ClassScan c : classes) {
            for (MethodInfo m : c.methods()) {
                if (TICK_METHODS.contains(m.name())) {
                    out.add(new HotEntrypoint(c.internalName(), m.name(), Heat.HOT));
                }
            }
        }
        return out;
    }
}
