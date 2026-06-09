package dev.pluginguard.engine.bytecode;

import dev.pluginguard.engine.model.ClassFile;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.util.ArrayList;
import java.util.List;

/**
 * Performs a single read-only ASM pass over a {@code .class} and collects everything the analyzers
 * need: header, methods, call sites and string constants.
 *
 * <p>ASM only <em>parses</em> the class file format; it never defines, links or initializes the
 * class in the JVM, so analyzing hostile bytecode is safe.
 */
public final class ClassScanner {

    private static final int API = Opcodes.ASM9;

    /** Per-class cap on retained string constants to bound memory on pathological inputs. */
    private static final int MAX_STRINGS_PER_CLASS = 4000;

    private ClassScanner() {
    }

    public static ClassScan scan(ClassFile cf) {
        Collector collector = new Collector(cf.internalName());
        try {
            ClassReader reader = new ClassReader(cf.bytes());
            reader.accept(collector, ClassReader.SKIP_FRAMES | ClassReader.SKIP_DEBUG);
        } catch (RuntimeException e) {
            // Malformed / truncated class — return what we have, flagged as not parsed.
            return new ClassScan(cf.internalName(), null, List.of(), 0, false,
                    List.of(), List.of(), List.of());
        }
        return collector.toScan();
    }

    private static final class Collector extends ClassVisitor {
        private final String fallbackName;
        private String internalName;
        private String superName;
        private List<String> interfaces = List.of();
        private int access;
        private final List<MethodInfo> methods = new ArrayList<>();
        private final List<Invocation> invocations = new ArrayList<>();
        private final List<String> strings = new ArrayList<>();

        Collector(String fallbackName) {
            super(API);
            this.fallbackName = fallbackName;
            this.internalName = fallbackName;
        }

        @Override
        public void visit(int version, int access, String name, String signature,
                          String superName, String[] interfaces) {
            this.internalName = name != null ? name : fallbackName;
            this.access = access;
            this.superName = superName;
            this.interfaces = interfaces != null ? List.of(interfaces) : List.of();
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor,
                                         String signature, String[] exceptions) {
            methods.add(new MethodInfo(name, descriptor));
            return new MethodCollector(name);
        }

        ClassScan toScan() {
            return new ClassScan(internalName, superName, interfaces, access, true,
                    List.copyOf(methods), List.copyOf(invocations), List.copyOf(strings));
        }

        private final class MethodCollector extends MethodVisitor {
            private final String methodName;

            MethodCollector(String methodName) {
                super(API);
                this.methodName = methodName;
            }

            @Override
            public void visitMethodInsn(int opcode, String owner, String name,
                                        String descriptor, boolean isInterface) {
                invocations.add(new Invocation(owner, name, descriptor, internalName, methodName));
            }

            @Override
            public void visitLdcInsn(Object value) {
                if (value instanceof String s && strings.size() < MAX_STRINGS_PER_CLASS) {
                    strings.add(s);
                }
            }
        }
    }
}
