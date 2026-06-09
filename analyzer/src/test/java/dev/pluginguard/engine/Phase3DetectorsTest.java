package dev.pluginguard.engine;

import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.ScanResult;
import dev.pluginguard.engine.model.Severity;
import dev.pluginguard.support.JarBuilder;
import dev.pluginguard.support.JarBuilder.Call;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Phase&nbsp;3 detectors: filesystem-mutation bytecode rules, the Foreign Function &amp; Memory
 * (Panama) native rule, and the ZIP central-directory/stream desync check. Each case is a synthetic
 * JAR whose classes are only parsed, never loaded.
 */
@SpringBootTest
class Phase3DetectorsTest {

    @Autowired
    AnalysisEngine engine;

    // --- Filesystem mutation -----------------------------------------------------------------

    @Test
    void makingAFileExecutableIsFlaggedHigh() {
        byte[] jar = new JarBuilder()
                .addClass("com/x/Dropper", "stage",
                        List.of(new Call("java/io/File", "setExecutable")), List.of())
                .addResource("plugin.yml", descriptor("com.x.Dropper"))
                .build();

        ScanResult result = engine.analyze("p3a", "dropper.jar", jar);

        Finding f = findRule(result, "BYTECODE_FILE_MAKE_EXECUTABLE");
        assertThat(f).isNotNull();
        assertThat(f.severity()).isEqualTo(Severity.HIGH);
    }

    @Test
    void plainFileWriteIsOnlyLowSeverity() {
        byte[] jar = new JarBuilder()
                .addClass("com/x/Saver", "save",
                        List.of(new Call("java/nio/file/Files", "write")), List.of())
                .addResource("plugin.yml", descriptor("com.x.Saver"))
                .build();

        ScanResult result = engine.analyze("p3b", "saver.jar", jar);

        Finding f = findRule(result, "BYTECODE_FILE_WRITE");
        assertThat(f).isNotNull();
        assertThat(f.severity()).isEqualTo(Severity.LOW);
    }

    // --- Foreign Function & Memory API (Panama) ----------------------------------------------

    @Test
    void foreignFunctionApiNativeCallIsFlagged() {
        byte[] jar = new JarBuilder()
                .addClass("com/x/Ffi", "call",
                        List.of(new Call("java/lang/foreign/Linker", "downcallHandle")), List.of())
                .addResource("plugin.yml", descriptor("com.x.Ffi"))
                .build();

        ScanResult result = engine.analyze("p3c", "ffi.jar", jar);

        Finding f = findRule(result, "BYTECODE_FOREIGN_FUNCTION");
        assertThat(f).isNotNull();
        assertThat(f.severity()).isEqualTo(Severity.HIGH);
    }

    // --- ZIP central-directory desync --------------------------------------------------------

    @Test
    void zipCentralDirectoryDesyncIsFlagged() {
        // What a front-to-back reader sees:
        byte[] visible = new JarBuilder()
                .addClass("com/example/Visible")
                .addResource("plugin.yml", descriptor("com.example.Visible"))
                .build();
        // What the JVM's class loader would actually load (referenced by the trailing central directory):
        byte[] hidden = new JarBuilder()
                .addClass("com/evil/Hidden", "run",
                        List.of(new Call("java/lang/Runtime", "exec")), List.of())
                .build();

        byte[] evil = concatZipPointingAtSecond(visible, hidden);

        ScanResult result = engine.analyze("p3d", "evil.jar", evil);

        Finding f = findRule(result, "STRUCTURE_ZIP_ANOMALY");
        assertThat(f).isNotNull();
        assertThat(f.severity()).isEqualTo(Severity.HIGH);
    }

    @Test
    void normalJarHasNoZipAnomaly() {
        byte[] jar = new JarBuilder()
                .addClass("com/example/Clean")
                .addResource("plugin.yml", descriptor("com.example.Clean"))
                .build();

        ScanResult result = engine.analyze("p3e", "clean.jar", jar);

        assertThat(ruleIds(result)).doesNotContain("STRUCTURE_ZIP_ANOMALY");
    }

    // --- helpers -----------------------------------------------------------------------------

    /**
     * Concatenates two archives and rewrites the trailing End Of Central Directory record so its
     * central-directory offset points at the second archive's directory in the combined buffer. This
     * is the "two archives glued together" tampering technique: a sequential reader sees the first
     * archive's entries, while the JVM trusts the second archive's directory.
     */
    private static byte[] concatZipPointingAtSecond(byte[] first, byte[] second) {
        byte[] out = new byte[first.length + second.length];
        System.arraycopy(first, 0, out, 0, first.length);
        System.arraycopy(second, 0, out, first.length, second.length);

        int eocdInSecond = lastEocd(second);
        long cdOffsetInSecond = u32(second, eocdInSecond + 16);
        int eocdInOut = lastEocd(out);
        writeU32(out, eocdInOut + 16, cdOffsetInSecond + first.length);
        return out;
    }

    private static int lastEocd(byte[] b) {
        for (int i = b.length - 22; i >= 0; i--) {
            if ((int) u32(b, i) == 0x06054b50) {
                return i;
            }
        }
        throw new IllegalStateException("no EOCD in test archive");
    }

    private static long u32(byte[] b, int off) {
        return (b[off] & 0xFFL) | ((b[off + 1] & 0xFFL) << 8)
                | ((b[off + 2] & 0xFFL) << 16) | ((b[off + 3] & 0xFFL) << 24);
    }

    private static void writeU32(byte[] b, int off, long value) {
        b[off] = (byte) (value & 0xFF);
        b[off + 1] = (byte) ((value >> 8) & 0xFF);
        b[off + 2] = (byte) ((value >> 16) & 0xFF);
        b[off + 3] = (byte) ((value >> 24) & 0xFF);
    }

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
