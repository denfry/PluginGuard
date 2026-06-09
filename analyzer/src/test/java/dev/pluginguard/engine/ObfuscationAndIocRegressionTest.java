package dev.pluginguard.engine;

import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.ScanResult;
import dev.pluginguard.engine.model.Severity;
import dev.pluginguard.support.JarBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Regressions distilled from a real-world scan of a nulled premium plugin (LagAssist 2.29
 * re-packed by a piracy site): indy-based obfuscation must drive the obfuscation score, version
 * strings and config placeholders must not be reported as C2 IPs, the NMS package prefix must not
 * look like the client's .minecraft directory, and piracy-site watermarks must be flagged.
 */
@SpringBootTest
class ObfuscationAndIocRegressionTest {

    @Autowired
    AnalysisEngine engine;

    @Test
    void indyObfuscationAndNonAsciiNamesDriveObfuscationScore() {
        JarBuilder b = new JarBuilder();
        for (int i = 0; i < 15; i++) {
            b.addClassWithIndy("com/prot/Indy" + i, new JarBuilder.Call("com/prot/Boot", "bsm"), null);
        }
        for (int i = 0; i < 12; i++) {
            // Greek-letter member names, as emitted by indy-protectors.
            b.addClass("com/prot/Holder" + i, "ξυστψεωκλμ" + i, List.of(), List.of());
        }

        ScanResult result = engine.analyze("ob1", "protected.jar", b.build());

        assertThat(result.obfuscationScore()).isGreaterThanOrEqualTo(55);
        assertThat(ruleIds(result)).contains("BYTECODE_INDY_CUSTOM_BOOTSTRAP");
        assertThat(ruleIds(result)).containsAnyOf("OBFUSCATION_MODERATE", "OBFUSCATION_HIGH");
    }

    @Test
    void cleanCodeKeepsObfuscationScoreLow() {
        byte[] jar = new JarBuilder()
                .addClass("com/good/ChatFormatter")
                .addClass("com/good/MessageListener")
                .build();

        ScanResult result = engine.analyze("ob2", "clean.jar", jar);

        assertThat(result.obfuscationScore()).isLessThan(25);
    }

    @Test
    void versionStringsAndConfigPlaceholdersAreNotHardcodedIpFindings() {
        byte[] jar = new JarBuilder()
                .addClass("com/app/Net", "run", List.of(), List.of(
                        "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.4; en-US; rv:1.9.2.2) Gecko/20100316 Firefox/3.6.2",
                        "allowed: 9.9.9.9.*",
                        "example: 1.2.3.4",
                        "connect to 185.220.101.50"))
                .build();

        ScanResult result = engine.analyze("ip1", "ips.jar", jar);

        List<String> ipEvidence = result.findings().stream()
                .filter(f -> f.ruleId().equals("IOC_HARDCODED_IP"))
                .map(Finding::evidence)
                .toList();
        assertThat(ipEvidence).containsExactly("185.220.101.50");
        assertThat(result.summaries().network()).contains("185.220.101.50");
    }

    @Test
    void nmsPackagePrefixIsNotASensitivePath() {
        byte[] jar = new JarBuilder()
                .addClass("com/app/Nms", "run", List.of(), List.of(
                        "net.minecraft.server.v1_16_R3.MinecraftServer"))
                .build();

        ScanResult result = engine.analyze("mc1", "nms.jar", jar);

        assertThat(ruleIds(result)).doesNotContain("IOC_SENSITIVE_PATH");
    }

    @Test
    void realMinecraftDirectoryPathIsStillFlagged() {
        byte[] jar = new JarBuilder()
                .addClass("com/app/Stealer", "run", List.of(), List.of(
                        "/home/user/.minecraft/saves"))
                .build();

        ScanResult result = engine.analyze("mc2", "dir.jar", jar);

        assertThat(result.findings())
                .anyMatch(f -> f.ruleId().equals("IOC_SENSITIVE_PATH") && ".minecraft".equals(f.evidence()));
    }

    @Test
    void nulledSiteWatermarkIsFlaggedHigh() {
        byte[] jar = new JarBuilder()
                .addClass("com/app/Main", "run", List.of(), List.of(
                        "https://black-minecraft.com/resources/3504/"))
                .addResource("plugin.yml",
                        "# Download it here: https://black-minecraft.com/resources/3504/\n"
                                + "name: Example\nversion: 1.0\nmain: com.app.Main\n")
                .build();

        ScanResult result = engine.analyze("nl1", "nulled.jar", jar);

        Finding nulled = result.findings().stream()
                .filter(f -> f.ruleId().equals("IOC_NULLED_DISTRIBUTION"))
                .findFirst()
                .orElseThrow(() -> new AssertionError("expected a nulled-distribution finding"));
        assertThat(nulled.severity()).isEqualTo(Severity.HIGH);
        assertThat(nulled.evidence()).contains("black-minecraft.com");
    }

    private static List<String> ruleIds(ScanResult result) {
        return result.findings().stream().map(Finding::ruleId).toList();
    }
}
