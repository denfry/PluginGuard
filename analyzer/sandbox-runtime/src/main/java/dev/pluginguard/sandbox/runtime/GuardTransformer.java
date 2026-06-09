package dev.pluginguard.sandbox.runtime;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

/**
 * Rewrites the plugin's dangerous call sites so each is preceded by a stack-neutral
 * {@code SandboxGuard.mark("TYPE|owner.name")} call. The marker records the attempt; the call then
 * proceeds and is blocked (if at all) by the {@link SandboxSecurityManager} or the container. This
 * way the behavior log captures reflectively-built or decoded calls that static analysis can't see.
 *
 * <p>Only plugin classes are touched — JDK, Bukkit-stub and runtime classes are skipped — and any
 * transform error falls back to the original bytes, so instrumentation can never break class loading.
 */
public final class GuardTransformer implements ClassFileTransformer {

    private static final String GUARD = "dev/pluginguard/sandbox/runtime/SandboxGuard";

    private static final String[] SKIP_PREFIXES = {
            "java/", "javax/", "jdk/", "sun/", "com/sun/", "org/bukkit/",
            "dev/pluginguard/sandbox/runtime/", "org/objectweb/asm/"
    };

    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain, byte[] classfileBuffer) {
        // The harness's InstrumentingClassLoader already instruments the classes it defines; skip
        // them here so a sink is not logged twice when both the agent and the loader are active.
        if (className == null || isInfrastructure(className) || loader instanceof InstrumentingClassLoader) {
            return null; // null = "no transform"
        }
        return instrument(classfileBuffer);
    }

    /** {@code true} if the internal class name belongs to the JDK / Bukkit stubs / sandbox runtime. */
    public static boolean isInfrastructure(String internalName) {
        for (String prefix : SKIP_PREFIXES) {
            if (internalName.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Returns instrumented bytes for a plugin class, or the original bytes if anything goes wrong.
     * Safe to call directly (used by the harness's {@link InstrumentingClassLoader} and by tests).
     */
    public static byte[] instrument(byte[] classBytes) {
        try {
            ClassReader reader = new ClassReader(classBytes);
            // COMPUTE_MAXS recomputes maxStack for the extra pushed string without loading classes
            // (COMPUTE_FRAMES would); existing stack-map frames are copied from the reader.
            ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS);
            reader.accept(new MarkingClassVisitor(writer), 0);
            return writer.toByteArray();
        } catch (RuntimeException | Error e) {
            return classBytes;
        }
    }

    private static final class MarkingClassVisitor extends ClassVisitor {
        MarkingClassVisitor(ClassVisitor next) {
            super(Opcodes.ASM9, next);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor,
                                         String signature, String[] exceptions) {
            MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
            return mv == null ? null : new MarkingMethodVisitor(mv);
        }
    }

    private static final class MarkingMethodVisitor extends MethodVisitor {
        MarkingMethodVisitor(MethodVisitor next) {
            super(Opcodes.ASM9, next);
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String descriptor,
                                    boolean isInterface) {
            String type = SinkRules.typeFor(owner, name);
            if (type != null) {
                // Stack-neutral marker inserted *before* the real call: push a constant, consume it.
                super.visitLdcInsn(type + "|" + owner.replace('/', '.') + "." + name);
                super.visitMethodInsn(Opcodes.INVOKESTATIC, GUARD, "mark",
                        "(Ljava/lang/String;)V", false);
            }
            super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
        }
    }
}
