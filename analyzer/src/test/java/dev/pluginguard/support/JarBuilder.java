package dev.pluginguard.support;

import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Handle;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Builds synthetic plugin JARs in memory for tests, using ASM to emit parseable {@code .class}
 * files. Generated classes are never loaded or executed — they exist only so the analyzer's
 * read-only ASM pass has realistic call sites and string constants to find.
 *
 * <p>Injected calls are emitted as stack-neutral {@code INVOKESTATIC ...()V} instructions: the
 * analyzer matches on owner + method name only, so the (otherwise unverifiable) bytecode is enough.
 */
public class JarBuilder {

    /** A call site to inject: matched by the analyzer as owner + name. */
    public record Call(String owner, String name) {
    }

    private final Map<String, byte[]> entries = new LinkedHashMap<>();

    /** Adds an empty, well-named class (e.g. for clean baselines / obfuscation stats). */
    public JarBuilder addClass(String internalName) {
        return addClass(internalName, "run", List.of(), List.of());
    }

    /** Adds a class with one method containing the given injected calls and string constants. */
    public JarBuilder addClass(String internalName, String methodName, List<Call> calls, List<String> strings) {
        entries.put(internalName + ".class", classBytes(internalName, methodName, calls, strings));
        return this;
    }

    /**
     * Adds a class whose method contains an {@code invokedynamic} wired to the given bootstrap
     * method, optionally with a method-handle argument (e.g. a {@code Runtime::exec} reference).
     */
    public JarBuilder addClassWithIndy(String internalName, Call bootstrap, Call argHandle) {
        entries.put(internalName + ".class", indyClassBytes(internalName, bootstrap, argHandle));
        return this;
    }

    /** Raw bytes of a synthetic class — for embedding (encoded blobs, disguised resources). */
    public static byte[] classOf(String internalName, List<Call> calls, List<String> strings) {
        return classBytes(internalName, "run", calls, strings);
    }

    public JarBuilder addResource(String name, String content) {
        entries.put(name, content.getBytes(StandardCharsets.UTF_8));
        return this;
    }

    public JarBuilder addRawEntry(String name, byte[] bytes) {
        entries.put(name, bytes);
        return this;
    }

    public byte[] build() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(baos)) {
            for (Map.Entry<String, byte[]> e : entries.entrySet()) {
                zos.putNextEntry(new ZipEntry(e.getKey()));
                zos.write(e.getValue());
                zos.closeEntry();
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return baos.toByteArray();
    }

    private static byte[] classBytes(String internalName, String methodName, List<Call> calls, List<String> strings) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC, internalName, null, "java/lang/Object", null);

        MethodVisitor ctor = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        ctor.visitCode();
        ctor.visitVarInsn(Opcodes.ALOAD, 0);
        ctor.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        ctor.visitInsn(Opcodes.RETURN);
        ctor.visitMaxs(0, 0);
        ctor.visitEnd();

        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_PUBLIC, methodName, "()V", null, null);
        mv.visitCode();
        for (String s : strings) {
            mv.visitLdcInsn(s);
            mv.visitInsn(Opcodes.POP);
        }
        for (Call c : calls) {
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, c.owner(), c.name(), "()V", false);
        }
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }

    private static byte[] indyClassBytes(String internalName, Call bootstrap, Call argHandle) {
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
        Handle bsm = new Handle(Opcodes.H_INVOKESTATIC, bootstrap.owner(), bootstrap.name(),
                "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)"
                        + "Ljava/lang/invoke/CallSite;", false);
        Object[] args = argHandle == null
                ? new Object[0]
                : new Object[]{new Handle(Opcodes.H_INVOKEVIRTUAL, argHandle.owner(), argHandle.name(),
                        "(Ljava/lang/String;)Ljava/lang/Process;", false)};
        mv.visitInvokeDynamicInsn("run", "()V", bsm, args);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }

    public static List<Call> calls(Call... c) {
        return new ArrayList<>(List.of(c));
    }
}
