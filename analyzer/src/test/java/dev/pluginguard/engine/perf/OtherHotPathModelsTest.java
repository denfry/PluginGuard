package dev.pluginguard.engine.perf;

import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.bytecode.MethodInfo;
import dev.pluginguard.engine.model.ArtifactType;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class OtherHotPathModelsTest {

    /** A hand-built ClassScan, bypassing JarBuilder, for annotation-only model tests. */
    private static ClassScan classWith(String internalName, MethodInfo... methods) {
        return new ClassScan(internalName, "java/lang/Object", List.of(), 0, true,
                List.of(methods), List.of(), List.of(), "", List.of());
    }

    @Test
    void forgeTickSubscriberIsHot() {
        ClassScan c = classWith("com/m/Handler",
                new MethodInfo("onTick", "(Lnet/minecraftforge/event/TickEvent$ServerTickEvent;)V",
                        List.of("Lnet/minecraftforge/eventbus/api/SubscribeEvent;")));
        List<HotEntrypoint> eps = new ForgeHotPathModel().entrypoints(List.of(c));
        assertThat(eps).anyMatch(e -> e.methodName().equals("onTick") && e.heat() == Heat.HOT);
    }

    @Test
    void fabricEndTickCallbackIsHot() {
        ClassScan c = classWith("com/m/Mod",
                new MethodInfo("onEndTick", "(Lnet/minecraft/server/MinecraftServer;)V", List.of()));
        List<HotEntrypoint> eps = new FabricHotPathModel().entrypoints(List.of(c));
        assertThat(eps).anyMatch(e -> e.methodName().equals("onEndTick") && e.heat() == Heat.HOT);
    }

    @Test
    void velocitySubscriberIsWarm() {
        ClassScan c = classWith("com/m/Listener",
                new MethodInfo("onPing", "(Lcom/velocitypowered/api/event/proxy/ProxyPingEvent;)V",
                        List.of("Lcom/velocitypowered/api/event/Subscribe;")));
        List<HotEntrypoint> eps = new ProxyHotPathModel().entrypoints(List.of(c));
        assertThat(eps).anyMatch(e -> e.methodName().equals("onPing") && e.heat() == Heat.WARM);
    }

    @Test
    void modelsSupportTheRightArtifacts() {
        assertThat(new ForgeHotPathModel().supports(ArtifactType.MOD_NEOFORGE)).isTrue();
        assertThat(new FabricHotPathModel().supports(ArtifactType.MOD_QUILT)).isTrue();
        assertThat(new ProxyHotPathModel().supports(ArtifactType.PLUGIN_VELOCITY)).isTrue();
    }
}
