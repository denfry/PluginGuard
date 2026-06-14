package dev.pluginguard.engine;

import dev.pluginguard.engine.model.Category;
import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.ScanResult;
import dev.pluginguard.engine.model.Severity;
import dev.pluginguard.engine.model.Verdict;
import dev.pluginguard.support.JarBuilder;
import dev.pluginguard.support.JarBuilder.Call;
import dev.pluginguard.support.TestPlugins;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Plugin-hardening detectors added on top of the Phase&nbsp;1 baseline: Minecraft platform-specific
 * sinks (console-command dispatch, operator control, client session token), the known-malware
 * signature table (fractureiser and a session-stealer RAT), the broader credential-theft IOCs, and
 * the hidden-operator-backdoor correlation. Synthetic JARs are parsed, never executed.
 */
@SpringBootTest
class PluginHardeningTest {

    @Autowired
    AnalysisEngine engine;

    // --- Minecraft platform sinks ------------------------------------------------------------

    @Test
    void consoleDispatchAndSetOpAreFlagged() {
        byte[] jar = new JarBuilder()
                .addClass("com/x/Op", "grant", List.of(
                        new Call("org/bukkit/Bukkit", "dispatchCommand"),
                        new Call("org/bukkit/entity/Player", "setOp")), List.of())
                .addResource("plugin.yml", descriptor("com.x.Op"))
                .build();

        ScanResult result = engine.analyze("op1", "op.jar", jar);

        assertThat(ruleIds(result)).contains("BYTECODE_BUKKIT_CONSOLE_DISPATCH", "BYTECODE_BUKKIT_SET_OP");
        assertThat(findRule(result, "BYTECODE_BUKKIT_SET_OP").category()).isEqualTo(Category.MINECRAFT);
    }

    @Test
    void clientSessionTokenAccessIsFlagged() {
        byte[] jar = new JarBuilder()
                .addClass("com/x/Steal", "init", List.of(
                        new Call("net/minecraft/client/Minecraft", "getAccessToken")), List.of())
                .addResource("plugin.yml", descriptor("com.x.Steal"))
                .build();

        ScanResult result = engine.analyze("st1", "steal.jar", jar);

        assertThat(ruleIds(result)).contains("BYTECODE_MC_SESSION_TOKEN");
    }

    // --- Known-malware signatures ------------------------------------------------------------

    @Test
    void fractureiserNamespaceIsCritical() {
        byte[] jar = new JarBuilder()
                .addClass("dev/neko/nekoclient/Client", "run", List.of(), List.of())
                .addResource("plugin.yml", descriptor("dev.neko.nekoclient.Client"))
                .build();

        ScanResult result = engine.analyze("fr1", "infected.jar", jar);

        Finding sig = findRule(result, "SIG_FRACTUREISER");
        assertThat(sig).isNotNull();
        assertThat(sig.severity()).isEqualTo(Severity.CRITICAL);
        assertThat(sig.category()).isEqualTo(Category.MALWARE_SIGNATURE);
        assertThat(result.verdict()).isEqualTo(Verdict.CRITICAL_RISK);
    }

    @Test
    void fractureiserC2HostInAStringIsFlagged() {
        byte[] jar = new JarBuilder()
                .addClass("com/x/Beacon", "tick", List.of(), List.of("https://files-8ie.pages.dev/ip"))
                .addResource("plugin.yml", descriptor("com.x.Beacon"))
                .build();

        ScanResult result = engine.analyze("fr2", "beacon.jar", jar);

        assertThat(ruleIds(result)).contains("SIG_FRACTUREISER");
    }

    @Test
    void sessionStealerRatSignatureIsFlagged() {
        byte[] jar = new JarBuilder()
                .addClass("dev/majanito/Main", "initializeWeedhack", List.of(),
                        List.of("https://whreceive.ru/files/jar/module"))
                .addResource("plugin.yml", descriptor("dev.majanito.Main"))
                .build();

        ScanResult result = engine.analyze("rat1", "rat.jar", jar);

        assertThat(ruleIds(result)).contains("SIG_MC_SESSION_STEALER_RAT");
    }

    // --- Broader credential IOCs -------------------------------------------------------------

    @Test
    void browserCredentialStorePathIsFlagged() {
        byte[] jar = new JarBuilder()
                .addClass("com/x/Loot", "run", List.of(),
                        List.of("AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\abc\\logins.json"))
                .addResource("plugin.yml", descriptor("com.x.Loot"))
                .build();

        ScanResult result = engine.analyze("bc1", "loot.jar", jar);

        assertThat(ruleIds(result)).contains("IOC_BROWSER_CREDENTIAL");
    }

    // --- Hidden operator backdoor correlation ------------------------------------------------

    @Test
    void hiddenOperatorBackdoorComboFires() {
        // Operator grant inside a binary that was repacked by a piracy ("nulled") site — privilege
        // escalation shipped through a tampered, watermarked build.
        byte[] jar = new JarBuilder()
                .addClass("com/x/Door", "trigger", List.of(
                        new Call("org/bukkit/entity/Player", "setOp")),
                        List.of("grabbed from https://blackspigot.com/resources/4242/"))
                .addResource("plugin.yml", descriptor("com.x.Door"))
                .build();

        ScanResult result = engine.analyze("door1", "door.jar", jar);

        Finding combo = findRule(result, "COMBO_OP_BACKDOOR");
        assertThat(combo).isNotNull();
        assertThat(combo.category()).isEqualTo(Category.COMBO);
        assertThat(combo.severity()).isEqualTo(Severity.HIGH);
        assertThat(combo.relatedRuleIds()).isNotEmpty();
    }

    // --- False-positive control --------------------------------------------------------------

    @Test
    void benignPluginRaisesNoneOfTheNewDetectors() {
        ScanResult result = engine.analyze("be1", "benign.jar", TestPlugins.benign());

        assertThat(ruleIds(result)).doesNotContain(
                "SIG_FRACTUREISER", "SIG_MC_SESSION_STEALER_RAT",
                "BYTECODE_BUKKIT_SET_OP", "BYTECODE_BUKKIT_CONSOLE_DISPATCH",
                "BYTECODE_MC_SESSION_TOKEN", "IOC_BROWSER_CREDENTIAL", "COMBO_OP_BACKDOOR");
    }

    // --- helpers -----------------------------------------------------------------------------

    private static String descriptor(String main) {
        return "name: Test\nversion: \"1.0\"\nmain: " + main + "\napi-version: \"1.21\"\n";
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
