package dev.pluginguard.engine.perf;

import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.bytecode.MethodInfo;
import dev.pluginguard.engine.model.ArtifactType;

import java.util.ArrayList;
import java.util.List;

/** Forge/NeoForge hot paths: @SubscribeEvent methods, hottest when the event is a tick event. */
public class ForgeHotPathModel implements HotPathModel {

    private static final String SUBSCRIBE_EVENT = "Lnet/minecraftforge/eventbus/api/SubscribeEvent;";

    @Override
    public boolean supports(ArtifactType t) {
        return t == ArtifactType.MOD_FORGE || t == ArtifactType.MOD_NEOFORGE;
    }

    @Override
    public List<HotEntrypoint> entrypoints(List<ClassScan> classes) {
        List<HotEntrypoint> out = new ArrayList<>();
        for (ClassScan c : classes) {
            for (MethodInfo m : c.methods()) {
                if (!m.annotations().contains(SUBSCRIBE_EVENT)) {
                    continue;
                }
                boolean tick = m.descriptor().contains("Tick");
                out.add(new HotEntrypoint(c.internalName(), m.name(), tick ? Heat.HOT : Heat.WARM));
            }
        }
        return out;
    }
}
