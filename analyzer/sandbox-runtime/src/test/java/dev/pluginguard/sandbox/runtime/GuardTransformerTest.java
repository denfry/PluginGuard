package dev.pluginguard.sandbox.runtime;

import org.junit.jupiter.api.Test;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Verifies the agent's bytecode instrumentation records a sink call when the class actually runs. */
class GuardTransformerTest {

    @Test
    void infrastructureClassesAreNotInstrumented() {
        assertTrue(GuardTransformer.isInfrastructure("java/lang/Runtime"));
        assertTrue(GuardTransformer.isInfrastructure("org/bukkit/plugin/java/JavaPlugin"));
        assertTrue(GuardTransformer.isInfrastructure("dev/pluginguard/sandbox/runtime/SandboxGuard"));
        assertFalse(GuardTransformer.isInfrastructure("com/evil/Backdoor"));
    }

    @Test
    void instrumentedSinkCallIsRecordedWhenExecuted() throws Exception {
        SandboxGuard.install(new BehaviorLog());

        byte[] original = probeClass();
        byte[] instrumented = GuardTransformer.instrument(original);
        assertFalse(Arrays.equals(original, instrumented), "bytes should change after instrumentation");

        Class<?> probe = new BytesLoader(getClass().getClassLoader())
                .define("probe.Probe", instrumented);
        Method run = probe.getMethod("run");
        run.invoke(null); // executes the (harmless) Class.forName call site

        List<BehaviorEvent> events = SandboxGuard.log().events();
        assertTrue(events.stream().anyMatch(e ->
                        "REFLECTION".equals(e.type()) && e.target() != null && e.target().contains("java.lang.Class.forName")),
                "expected a REFLECTION event for Class.forName, got: " + events);
    }

    /** {@code public class probe.Probe { public static void run() { Class.forName("java.lang.String"); } }} */
    private static byte[] probeClass() {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V17, Opcodes.ACC_PUBLIC, "probe/Probe", null, "java/lang/Object", null);

        MethodVisitor ctor = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        ctor.visitCode();
        ctor.visitVarInsn(Opcodes.ALOAD, 0);
        ctor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        ctor.visitInsn(Opcodes.RETURN);
        ctor.visitMaxs(0, 0);
        ctor.visitEnd();

        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC, "run", "()V", null, null);
        mv.visitCode();
        mv.visitLdcInsn("java.lang.String");
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Class", "forName",
                "(Ljava/lang/String;)Ljava/lang/Class;", false);
        mv.visitInsn(Opcodes.POP);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }

    private static final class BytesLoader extends ClassLoader {
        BytesLoader(ClassLoader parent) {
            super(parent);
        }

        Class<?> define(String name, byte[] bytes) {
            return defineClass(name, bytes, 0, bytes.length);
        }
    }
}
