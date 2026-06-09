package dev.pluginguard.engine.bytecode;

import dev.pluginguard.engine.bytecode.TaintInterpreter.TaintValue;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.Frame;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Runs the {@link TaintInterpreter} dataflow over each method of a parsed class and records every
 * point where externally-influenced data reaches a dangerous sink. The current sink is
 * {@code defineClass}/{@code defineHiddenClass} reached by a tainted {@code byte[]} — i.e. a class is
 * materialised from network or decoded/decrypted bytes, the data-flow-confirmed form of a remote or
 * encrypted payload loader.
 *
 * <p>Read-only and best-effort: if the dataflow cannot be computed for a method (malformed
 * bytecode), that method simply contributes no flows.
 */
public final class TaintScanner {

    private static final String BYTE_ARRAY = "[B";
    private static final Set<String> DEFINE_CLASS_METHODS = Set.of("defineClass", "defineHiddenClass");

    private TaintScanner() {
    }

    public static List<TaintFlow> scan(ClassNode node) {
        List<TaintFlow> flows = new ArrayList<>();
        for (MethodNode method : node.methods) {
            if (method.instructions.size() == 0) {
                continue;
            }
            try {
                scanMethod(node.name, method, flows);
            } catch (Throwable t) {
                // best-effort: a method whose dataflow cannot be computed contributes no flows
            }
        }
        return flows;
    }

    private static void scanMethod(String owner, MethodNode method, List<TaintFlow> flows) throws Exception {
        Analyzer<TaintValue> analyzer = new Analyzer<>(new TaintInterpreter());
        Frame<TaintValue>[] frames = analyzer.analyze(owner, method);
        AbstractInsnNode[] insns = method.instructions.toArray();

        for (int i = 0; i < insns.length; i++) {
            if (!(insns[i] instanceof MethodInsnNode m) || !DEFINE_CLASS_METHODS.contains(m.name)
                    || frames[i] == null) {
                continue;
            }
            String source = taintedByteArrayArg(m.desc, frames[i]);
            if (source != null) {
                flows.add(new TaintFlow(TaintFlow.REMOTE_CODE_LOAD, method.name, source));
            }
        }
    }

    /** The taint label of the first tainted {@code byte[]} argument of {@code desc}, or null. */
    private static String taintedByteArrayArg(String desc, Frame<TaintValue> frame) {
        Type[] args = Type.getArgumentTypes(desc);
        int n = args.length;
        for (int k = 0; k < n; k++) {
            if (BYTE_ARRAY.equals(args[k].getDescriptor())) {
                int index = frame.getStackSize() - (n - k);
                if (index >= 0 && index < frame.getStackSize()) {
                    TaintValue v = frame.getStack(index);
                    if (v != null && v.tainted()) {
                        return v.source;
                    }
                }
            }
        }
        return null;
    }
}
