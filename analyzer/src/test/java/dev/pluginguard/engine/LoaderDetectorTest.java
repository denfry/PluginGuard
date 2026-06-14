package dev.pluginguard.engine;

import dev.pluginguard.engine.model.ArtifactType;
import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.ScanResult;
import dev.pluginguard.support.JarBuilder;
import dev.pluginguard.support.JarBuilder.Call;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Multi-format scaffold: the loader detector must classify plugins, mods and packs from their
 * descriptors/layout, the report must carry the {@link ArtifactType}, mods/packs must not be
 * mis-flagged for lacking a {@code plugin.yml}, and the existing bytecode engine must still apply
 * to a mod jar (it is just another JAR full of classes).
 */
@SpringBootTest
class LoaderDetectorTest {

    @Autowired
    AnalysisEngine engine;

    @Test
    void bukkitPluginIsClassified() {
        byte[] jar = new JarBuilder()
                .addClass("com/x/Main")
                .addResource("plugin.yml", "name: P\nversion: \"1.0\"\nmain: com.x.Main\n")
                .build();

        ScanResult result = engine.analyze("p1", "plugin.jar", jar);

        assertThat(result.artifactType()).isEqualTo(ArtifactType.PLUGIN_BUKKIT);
        assertThat(result.platform()).isEqualTo("Bukkit/Spigot/Paper");
    }

    @Test
    void fabricModIsClassifiedAndNotFlaggedForMissingPluginYml() {
        byte[] jar = new JarBuilder()
                .addClass("com/mod/ExampleMod")
                .addResource("fabric.mod.json",
                        "{\"schemaVersion\":1,\"id\":\"example\",\"version\":\"1.0\"}")
                .build();

        ScanResult result = engine.analyze("f1", "example-mod.jar", jar);

        assertThat(result.artifactType()).isEqualTo(ArtifactType.MOD_FABRIC);
        assertThat(result.platform()).isEqualTo("Fabric");
        assertThat(ruleIds(result)).doesNotContain("YML_MISSING");
    }

    @Test
    void forgeAndNeoForgeModsAreClassified() {
        byte[] forge = new JarBuilder()
                .addClass("com/mod/ForgeMod")
                .addResource("META-INF/mods.toml", "modLoader=\"javafml\"\n[[mods]]\nmodId=\"example\"\n")
                .build();
        byte[] neo = new JarBuilder()
                .addClass("com/mod/NeoMod")
                .addResource("META-INF/neoforge.mods.toml", "modLoader=\"javafml\"\n[[mods]]\nmodId=\"example\"\n")
                .build();

        assertThat(engine.analyze("fg1", "forge.jar", forge).artifactType()).isEqualTo(ArtifactType.MOD_FORGE);
        assertThat(engine.analyze("ng1", "neo.jar", neo).artifactType()).isEqualTo(ArtifactType.MOD_NEOFORGE);
    }

    @Test
    void resourcePackVsDataPackAreDistinguished() {
        byte[] resourcePack = new JarBuilder()
                .addResource("pack.mcmeta", "{\"pack\":{\"pack_format\":34,\"description\":\"x\"}}")
                .addRawEntry("assets/minecraft/textures/block/stone.png", new byte[]{(byte) 0x89, 'P', 'N', 'G'})
                .build();
        byte[] dataPack = new JarBuilder()
                .addResource("pack.mcmeta", "{\"pack\":{\"pack_format\":48,\"description\":\"x\"}}")
                .addResource("data/example/function/tick.mcfunction", "say hi")
                .build();

        assertThat(engine.analyze("rp1", "pack.zip", resourcePack).artifactType())
                .isEqualTo(ArtifactType.RESOURCE_PACK);
        assertThat(engine.analyze("dp1", "datapack.zip", dataPack).artifactType())
                .isEqualTo(ArtifactType.DATA_PACK);
    }

    @Test
    void bytecodeEngineStillAppliesToAMod() {
        // A mod is just a JAR full of classes — the full static engine must run on it.
        byte[] jar = new JarBuilder()
                .addClass("com/mod/Bad", "run", List.of(new Call("java/lang/Runtime", "exec")), List.of())
                .addResource("fabric.mod.json", "{\"schemaVersion\":1,\"id\":\"bad\",\"version\":\"1.0\"}")
                .build();

        ScanResult result = engine.analyze("m1", "bad-mod.jar", jar);

        assertThat(result.artifactType()).isEqualTo(ArtifactType.MOD_FABRIC);
        assertThat(ruleIds(result)).contains("BYTECODE_RUNTIME_EXEC");
    }

    private static List<String> ruleIds(ScanResult result) {
        return result.findings().stream().map(Finding::ruleId).toList();
    }
}
