package dev.pluginguard.engine;

import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.ScanResult;
import dev.pluginguard.support.JarBuilder;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Handle;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * String-constant folding (Phase&nbsp;2 deep static): reflective targets assembled from more than one
 * {@code ldc} — a local variable, a {@link StringBuilder} chain, {@code invokedynamic} concatenation —
 * are resolved by the {@link dev.pluginguard.engine.bytecode.StringConstantInterpreter} dataflow pass.
 * The StringBuilder and invokedynamic cases cannot be resolved by the nearest-ldc fallback (an
 * intervening call clears it), so they prove the interpreter is doing the work.
 */
@SpringBootTest
class Phase4StringResolutionTest {

    @Autowired
    AnalysisEngine engine;

    @Test
    void classNameFromLocalVariableIsResolved() {
        byte[] cls = clazz("com/x/LocalVar", mv -> {
            mv.visitLdcInsn("java.lang.Runtime");
            mv.visitVarInsn(Opcodes.ASTORE, 1);
            mv.visitVarInsn(Opcodes.ALOAD, 1);
            forName(mv);
            mv.visitInsn(Opcodes.POP);
        });
        assertThat(ruleIds(scan("s1", "localvar.jar", "com.x.LocalVar", cls)))
                .contains("BYTECODE_REFLECTIVE_DANGEROUS_CLASS");
    }

    @Test
    void classNameBuiltWithStringBuilderIsResolved() {
        byte[] cls = clazz("com/x/Sb", mv -> {
            mv.visitTypeInsn(Opcodes.NEW, "java/lang/StringBuilder");
            mv.visitInsn(Opcodes.DUP);
            mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false);
            mv.visitLdcInsn("java.lang.");
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                    "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
            mv.visitLdcInsn("Runtime");
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append",
                    "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false);
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "toString",
                    "()Ljava/lang/String;", false);
            forName(mv);
            mv.visitInsn(Opcodes.POP);
        });
        assertThat(ruleIds(scan("s2", "sb.jar", "com.x.Sb", cls)))
                .contains("BYTECODE_REFLECTIVE_DANGEROUS_CLASS");
    }

    @Test
    void classNameFromInvokeDynamicConcatIsResolved() {
        byte[] cls = clazz("com/x/Concat", mv -> {
            mv.visitLdcInsn("java.lang.");
            mv.visitVarInsn(Opcodes.ASTORE, 1);
            mv.visitLdcInsn("Runtime");
            mv.visitVarInsn(Opcodes.ASTORE, 2);
            mv.visitVarInsn(Opcodes.ALOAD, 1);
            mv.visitVarInsn(Opcodes.ALOAD, 2);
            Handle bsm = new Handle(Opcodes.H_INVOKESTATIC, "java/lang/invoke/StringConcatFactory",
                    "makeConcatWithConstants",
                    "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;"
                            + "[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;", false);
            // recipe "": two dynamic arguments, no constants
            mv.visitInvokeDynamicInsn("makeConcatWithConstants",
                    "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", bsm, "");
            forName(mv);
            mv.visitInsn(Opcodes.POP);
        });
        assertThat(ruleIds(scan("s3", "concat.jar", "com.x.Concat", cls)))
                .contains("BYTECODE_REFLECTIVE_DANGEROUS_CLASS");
    }

    @Test
    void dangerousMethodNameViaMethodHandlesFindIsResolved() {
        byte[] cls = clazz("com/x/Find", mv -> {
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/invoke/MethodHandles", "lookup",
                    "()Ljava/lang/invoke/MethodHandles$Lookup;", false);
            mv.visitLdcInsn(Type.getObjectType("java/lang/Runtime"));
            mv.visitLdcInsn("exec");
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/invoke/MethodHandles$Lookup", "findVirtual",
                    "(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/invoke/MethodHandle;", false);
            mv.visitInsn(Opcodes.POP);
        });
        assertThat(ruleIds(scan("s4", "find.jar", "com.x.Find", cls)))
                .contains("BYTECODE_REFLECTIVE_DANGEROUS_METHOD");
    }

    @Test
    void unresolvableClassNameDoesNotFalselyFire() {
        // The name comes from an unknown method return, so it must not resolve to a dangerous class.
        byte[] cls = clazz("com/x/Unknown", mv -> {
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, "com/x/Source", "name", "()Ljava/lang/String;", false);
            forName(mv);
            mv.visitInsn(Opcodes.POP);
        });
        assertThat(ruleIds(scan("s5", "unknown.jar", "com.x.Unknown", cls)))
                .doesNotContain("BYTECODE_REFLECTIVE_DANGEROUS_CLASS");
    }

    // --- helpers -----------------------------------------------------------------------------

    private static void forName(MethodVisitor mv) {
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Class", "forName",
                "(Ljava/lang/String;)Ljava/lang/Class;", false);
    }

    /** Builds a class with a no-arg constructor and a {@code run()} method holding the given body. */
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

    private static List<String> ruleIds(ScanResult result) {
        return result.findings().stream().map(Finding::ruleId).toList();
    }
}
