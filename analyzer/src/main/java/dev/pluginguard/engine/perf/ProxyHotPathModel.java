package dev.pluginguard.engine.perf;

import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.bytecode.MethodInfo;
import dev.pluginguard.engine.model.ArtifactType;

import java.util.ArrayList;
import java.util.List;

/** Proxy (BungeeCord/Velocity) hot paths: per-connection event handlers. No server tick. */
public class ProxyHotPathModel implements HotPathModel {

    private static final String BUNGEE_HANDLER = "Lnet/md_5/bungee/event/EventHandler;";
    private static final String VELOCITY_SUBSCRIBE = "Lcom/velocitypowered/api/event/Subscribe;";

    @Override
    public boolean supports(ArtifactType t) {
        return t == ArtifactType.PLUGIN_BUNGEE || t == ArtifactType.PLUGIN_VELOCITY;
    }

    @Override
    public List<HotEntrypoint> entrypoints(List<ClassScan> classes) {
        List<HotEntrypoint> out = new ArrayList<>();
        for (ClassScan c : classes) {
            for (MethodInfo m : c.methods()) {
                if (m.annotations().contains(BUNGEE_HANDLER) || m.annotations().contains(VELOCITY_SUBSCRIBE)) {
                    out.add(new HotEntrypoint(c.internalName(), m.name(), Heat.WARM));
                }
            }
        }
        return out;
    }
}
