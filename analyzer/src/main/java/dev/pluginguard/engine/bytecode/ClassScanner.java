package dev.pluginguard.engine.bytecode;

import dev.pluginguard.engine.bytecode.StringConstantInterpreter.StrValue;
import dev.pluginguard.engine.model.ClassFile;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.FrameNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.Frame;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Performs a single read-only ASM pass over a {@code .class} and collects everything the analyzers
 * need: header, methods, call sites (including {@code invokedynamic} bootstraps and their
 * method-handle arguments) and string constants.
 *
 * <p>Call-site string operands (the argument to {@code Class.forName("...")}, {@code getMethod("...")},
 * {@code MethodHandles.Lookup.findVirtual(..,"...",..)}) are resolved with a
 * {@link StringConstantInterpreter} dataflow pass, so a name assembled from a local variable, a
 * {@link StringBuilder} chain or {@code invokedynamic} string concatenation is still recovered. When
 * that analysis cannot run (malformed bytecode), it falls back to the nearest preceding string
 * constant — the original best-effort heuristic — so resolution only ever improves, never regresses.
 *
 * <p>ASM only <em>parses</em> the class file format; it never defines, links or initializes the
 * class in the JVM, so analyzing hostile bytecode is safe.
 */
public final class ClassScanner {

    private static final int PARSING_OPTIONS = ClassReader.SKIP_FRAMES | ClassReader.SKIP_DEBUG;

    /** Per-class cap on retained string constants to bound memory on pathological inputs. */
    private static final int MAX_STRINGS_PER_CLASS = 4000;

    private static final String STRING_DESC = "Ljava/lang/String;";

    private ClassScanner() {
    }

    public static ClassScan scan(ClassFile cf) {
        ClassNode node = new ClassNode();
        try {
            new ClassReader(cf.bytes()).accept(node, PARSING_OPTIONS);
        } catch (RuntimeException | Error e) {
            // Malformed / truncated class — return what we have, flagged as not parsed.
            return new ClassScan(cf.internalName(), null, List.of(), 0, false,
                    List.of(), List.of(), List.of(), cf.container(), List.of());
        }

        String internalName = node.name != null ? node.name : cf.internalName();
        Map<String, String> constStringFields = collectConstStringFields(node);

        List<MethodInfo> methods = new ArrayList<>();
        List<Invocation> invocations = new ArrayList<>();
        List<String> strings = new ArrayList<>();

        for (MethodNode method : node.methods) {
            methods.add(new MethodInfo(method.name, method.desc, annotationDescriptors(method)));
            scanMethod(node.name, method, constStringFields, invocations, strings);
        }

        return new ClassScan(internalName, node.superName,
                node.interfaces != null ? List.copyOf(node.interfaces) : List.of(),
                node.access, true, List.copyOf(methods), List.copyOf(invocations),
                List.copyOf(strings), cf.container(), TaintScanner.scan(node));
    }

    /** Scans raw class bytes that did not come from a {@link ClassFile} (e.g. a decoded payload). */
    public static ClassScan scanBytes(String fallbackName, byte[] bytes, String container) {
        return scan(new ClassFile(fallbackName, bytes, container));
    }

    private static void scanMethod(String owner, MethodNode method,
                                   Map<String, String> constStringFields,
                                   List<Invocation> invocations, List<String> strings) {
        Map<AbstractInsnNode, String> resolvedOperands = resolveOperands(owner, method, constStringFields);

        // Fallback operand: the nearest preceding string constant, consumed by the next call site.
        String pendingLdc = null;
        for (AbstractInsnNode insn : method.instructions) {
            if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof String s) {
                if (strings.size() < MAX_STRINGS_PER_CLASS) {
                    strings.add(s);
                }
                pendingLdc = s;
            } else if (insn instanceof MethodInsnNode m) {
                String operand = resolvedOperands.getOrDefault(insn, pendingLdc);
                invocations.add(new Invocation(m.owner, m.name, m.desc, owner, method.name,
                        InvocationKind.INVOKE, operand));
                pendingLdc = null;
            } else if (insn instanceof InvokeDynamicInsnNode indy) {
                // The bootstrap method itself (LambdaMetafactory / StringConcatFactory / custom).
                invocations.add(new Invocation(indy.bsm.getOwner(), indy.bsm.getName(), indy.bsm.getDesc(),
                        owner, method.name, InvocationKind.INVOKE_DYNAMIC, indy.name));
                // Method-handle arguments often point at the *actual* target (e.g. a Runtime::exec
                // method reference). Recorded as plain calls so the normal rule table flags them.
                for (Object arg : indy.bsmArgs) {
                    if (arg instanceof Handle h) {
                        invocations.add(new Invocation(h.getOwner(), h.getName(), h.getDesc(),
                                owner, method.name, InvocationKind.INVOKE, null));
                    }
                }
                pendingLdc = null;
            }
        }
    }

    /**
     * Runs the String-folding dataflow pass and maps each invoke instruction to the resolved value of
     * its first {@code String} argument, when known. On any analysis failure the map is empty, so the
     * caller falls back to the nearest-preceding-ldc heuristic.
     */
    private static Map<AbstractInsnNode, String> resolveOperands(String owner, MethodNode method,
                                                                 Map<String, String> constStringFields) {
        Map<AbstractInsnNode, String> resolved = new HashMap<>();
        if (method.instructions.size() == 0) {
            return resolved;
        }
        try {
            Analyzer<StrValue> analyzer = new Analyzer<>(new StringConstantInterpreter(constStringFields));
            Frame<StrValue>[] frames = analyzer.analyze(owner, method);
            AbstractInsnNode[] insns = method.instructions.toArray();
            for (int i = 0; i < insns.length; i++) {
                if (!(insns[i] instanceof MethodInsnNode m) || frames[i] == null) {
                    continue;
                }
                String value = firstStringArg(m.desc, frames[i]);
                if (value != null) {
                    resolved.put(insns[i], value);
                }
            }
        } catch (Throwable t) {
            resolved.clear(); // degrade gracefully to the fallback heuristic
        }
        return resolved;
    }

    /** The folded value of the first {@code String}-typed parameter on the stack before {@code desc}. */
    private static String firstStringArg(String desc, Frame<StrValue> frame) {
        Type[] args = Type.getArgumentTypes(desc);
        int firstString = -1;
        for (int k = 0; k < args.length; k++) {
            if (STRING_DESC.equals(args[k].getDescriptor())) {
                firstString = k;
                break;
            }
        }
        if (firstString < 0) {
            return null;
        }
        // The stack top is the last argument; argument k sits (n-1-k) entries below it.
        int entryFromTop = (args.length - 1) - firstString;
        int index = frame.getStackSize() - 1 - entryFromTop;
        if (index < 0 || index >= frame.getStackSize()) {
            return null;
        }
        StrValue value = frame.getStack(index);
        return value == null ? null : value.text;
    }

    /**
     * Constant String values of this class's static fields: from a {@code ConstantValue} attribute and
     * from a simple {@code ldc → putstatic} in {@code <clinit>} (a non-final static set to a literal).
     */
    private static Map<String, String> collectConstStringFields(ClassNode node) {
        Map<String, String> out = new HashMap<>();
        for (FieldNode field : node.fields) {
            if ((field.access & Opcodes.ACC_STATIC) != 0 && field.value instanceof String s) {
                out.put(node.name + "." + field.name, s);
            }
        }
        for (MethodNode method : node.methods) {
            if (!"<clinit>".equals(method.name)) {
                continue;
            }
            for (AbstractInsnNode insn : method.instructions) {
                if (insn.getOpcode() == Opcodes.PUTSTATIC) {
                    FieldInsnNode f = (FieldInsnNode) insn;
                    if (STRING_DESC.equals(f.desc) && node.name.equals(f.owner)
                            && previousReal(insn) instanceof LdcInsnNode ldc && ldc.cst instanceof String s) {
                        out.put(f.owner + "." + f.name, s);
                    }
                }
            }
        }
        return out;
    }

    /** Descriptors of all (visible + invisible) annotations declared on a method. */
    private static List<String> annotationDescriptors(MethodNode method) {
        List<String> out = new ArrayList<>();
        if (method.visibleAnnotations != null) {
            for (var a : method.visibleAnnotations) {
                out.add(a.desc);
            }
        }
        if (method.invisibleAnnotations != null) {
            for (var a : method.invisibleAnnotations) {
                out.add(a.desc);
            }
        }
        return out;
    }

    /** The previous instruction, skipping labels, line numbers and frame pseudo-nodes. */
    private static AbstractInsnNode previousReal(AbstractInsnNode insn) {
        AbstractInsnNode p = insn.getPrevious();
        while (p instanceof LabelNode || p instanceof LineNumberNode || p instanceof FrameNode) {
            p = p.getPrevious();
        }
        return p;
    }
}
