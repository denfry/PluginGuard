package dev.pluginguard.engine;

import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.ScanResult;
import dev.pluginguard.engine.model.Severity;
import dev.pluginguard.engine.model.Verdict;
import dev.pluginguard.support.TestPlugins;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class AnalysisEngineTest {

    @Autowired
    AnalysisEngine engine;

    @Test
    void benignPluginScoresWellWithNoSeriousFindings() {
        ScanResult result = engine.analyze("t1", "benignchat.jar", TestPlugins.benign());

        assertThat(result.score()).isGreaterThanOrEqualTo(70);
        assertThat(result.verdict()).isIn(Verdict.LOW_RISK, Verdict.MINIMAL_RISK);
        assertThat(result.counts().critical()).isZero();
        assertThat(result.counts().high()).isZero();
        assertThat(result.platform()).isEqualTo("Bukkit/Spigot/Paper");
        assertThat(result.pluginInfo()).isNotNull();
        assertThat(result.pluginInfo().name()).isEqualTo("BenignChat");
        assertThat(result.mainClass()).isEqualTo("com.example.benign.BenignPlugin");
        // The benign GitHub URL is captured as a network indicator but raises no finding.
        assertThat(result.summaries().network()).contains("api.github.com");
        assertThat(ruleIds(result)).doesNotContain("YML_MAIN_MISSING");
    }

    @Test
    void maliciousPluginIsCriticalAndDetectsKeyBehaviours() {
        ScanResult result = engine.analyze("t2", "evil.jar", TestPlugins.malicious());

        assertThat(result.score()).isLessThanOrEqualTo(15);
        assertThat(result.verdict()).isIn(Verdict.CRITICAL_RISK, Verdict.HIGH_RISK);
        assertThat(result.counts().high() + result.counts().critical()).isGreaterThanOrEqualTo(4);

        assertThat(ruleIds(result)).contains(
                "BYTECODE_RUNTIME_EXEC",
                "BYTECODE_URL_CLASSLOADER",
                "BYTECODE_DEFINE_CLASS",
                "IOC_DISCORD_WEBHOOK",
                "IOC_SHELL_COMMAND",
                "IOC_CREDENTIAL_TARGET",
                "YML_BACKDOOR_COMMAND",
                "YML_WILDCARD_PERMISSION");

        // The correlation engine should fuse the individual signals into combo verdicts.
        assertThat(ruleIds(result)).contains(
                "COMBO_REMOTE_CODE_LOADER",
                "COMBO_CREDENTIAL_STEALER");

        assertThat(result.summaries().network()).contains("discord.com", "185.220.101.50");
        assertThat(result.obfuscationScore()).isGreaterThanOrEqualTo(50);
    }

    @Test
    void nonJarUploadIsFlagged() {
        ScanResult result = engine.analyze("t3", "fake.jar", TestPlugins.notAJar());

        assertThat(ruleIds(result)).contains("STRUCTURE_NOT_A_JAR");
        assertThat(result.score()).isLessThan(70);
    }

    @Test
    void nativeLibraryIsFlaggedHigh() {
        ScanResult result = engine.analyze("t4", "nativechat.jar", TestPlugins.withNativeLibrary());

        Finding nativeFinding = result.findings().stream()
                .filter(f -> f.ruleId().equals("STRUCTURE_NATIVE_FILE"))
                .findFirst()
                .orElseThrow(() -> new AssertionError("expected a native-file finding"));
        assertThat(nativeFinding.severity()).isEqualTo(Severity.HIGH);
        assertThat(nativeFinding.evidence()).contains("helper.dll");
    }

    private static List<String> ruleIds(ScanResult result) {
        return result.findings().stream().map(Finding::ruleId).toList();
    }
}
