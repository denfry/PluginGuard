package dev.pluginguard.engine;

import dev.pluginguard.engine.model.Category;
import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.ScanResult;
import dev.pluginguard.engine.model.Severity;
import dev.pluginguard.support.JarBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** Mod-descriptor parsing (Fabric/Quilt/Forge/NeoForge) and mod-specific capability detection. */
@SpringBootTest
class ModAnalyzerTest {

    @Autowired
    AnalysisEngine engine;

    @Test
    void fabricDescriptorIsParsedIntoPluginInfoAndDependencies() {
        String fmj = """
                {
                  "schemaVersion": 1,
                  "id": "example",
                  "name": "Example Mod",
                  "version": "1.2.3",
                  "authors": ["Alice", {"name": "Bob"}],
                  "depends": {"fabricloader": ">=0.15", "minecraft": "1.20.x"},
                  "entrypoints": {"main": ["com.mod.ExampleMod"]},
                  "accessWidener": "example.accesswidener"
                }
                """;
        byte[] jar = new JarBuilder()
                .addClass("com/mod/ExampleMod")
                .addResource("fabric.mod.json", fmj)
                .build();

        ScanResult result = engine.analyze("fp1", "example.jar", jar);

        assertThat(result.pluginInfo()).isNotNull();
        assertThat(result.pluginInfo().name()).isEqualTo("Example Mod");
        assertThat(result.pluginInfo().version()).isEqualTo("1.2.3");
        assertThat(result.pluginInfo().main()).isEqualTo("com.mod.ExampleMod");
        assertThat(result.pluginInfo().authors()).contains("Alice", "Bob");
        assertThat(result.pluginInfo().depend()).contains("fabricloader", "minecraft");
        assertThat(result.summaries().dependencies()).anyMatch(d -> d.name().equals("fabricloader"));
        assertThat(ruleIds(result)).contains("MOD_ACCESS_WIDENER");
        assertThat(ruleIds(result)).doesNotContain("YML_MISSING");
    }

    @Test
    void forgeModsTomlIsParsed() {
        byte[] jar = new JarBuilder()
                .addClass("com/mod/ForgeMod")
                .addResource("META-INF/mods.toml", """
                        modLoader="javafml"
                        loaderVersion="[46,)"
                        license="MIT"
                        [[mods]]
                        modId="examplemod"
                        version="2.0.0"
                        displayName="Example Forge Mod"
                        authors="Me"
                        """)
                .build();

        ScanResult result = engine.analyze("ft1", "forge.jar", jar);

        assertThat(result.pluginInfo()).isNotNull();
        assertThat(result.pluginInfo().name()).isEqualTo("Example Forge Mod");
        assertThat(result.pluginInfo().version()).isEqualTo("2.0.0");
    }

    @Test
    void forgeCoremodTransformerIsFlaggedHigh() {
        byte[] jar = new JarBuilder()
                .addClassImplementing("com/mod/CoreMod", "net/minecraftforge/fml/relauncher/IFMLLoadingPlugin")
                .addResource("META-INF/mods.toml", "modLoader=\"javafml\"\n[[mods]]\nmodId=\"core\"\nversion=\"1.0\"\n")
                .build();

        ScanResult result = engine.analyze("cm1", "core.jar", jar);

        Finding coremod = findRule(result, "MOD_COREMOD_TRANSFORMER");
        assertThat(coremod).isNotNull();
        assertThat(coremod.severity()).isEqualTo(Severity.HIGH);
        assertThat(coremod.category()).isEqualTo(Category.MINECRAFT);
    }

    @Test
    void mixinConfigPluginIsFlaggedMedium() {
        byte[] jar = new JarBuilder()
                .addClassImplementing("com/mod/Cfg",
                        "org/spongepowered/asm/mixin/extensibility/IMixinConfigPlugin")
                .addResource("fabric.mod.json", "{\"schemaVersion\":1,\"id\":\"m\",\"version\":\"1.0\"}")
                .build();

        ScanResult result = engine.analyze("mc1", "m.jar", jar);

        Finding plugin = findRule(result, "MOD_MIXIN_CONFIG_PLUGIN");
        assertThat(plugin).isNotNull();
        assertThat(plugin.severity()).isEqualTo(Severity.MEDIUM);
    }

    private static Finding findRule(ScanResult result, String ruleId) {
        return result.findings().stream()
                .filter(f -> f.ruleId().equals(ruleId))
                .findFirst()
                .orElse(null);
    }

    private static List<String> ruleIds(ScanResult result) {
        return result.findings().stream().map(Finding::ruleId).toList();
    }
}
