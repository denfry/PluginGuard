package dev.pluginguard.engine.bytecode;

import java.util.List;

/**
 * The result of one read-only ASM pass over a single {@code .class}. Produced by
 * {@link ClassScanner} and consumed by the bytecode, string/IOC and obfuscation analyzers, so
 * each class is parsed exactly once.
 *
 * @param internalName    JVM internal name of the class
 * @param superName       super-class internal name (may be {@code null})
 * @param interfaces      implemented interface internal names
 * @param access          class access flags
 * @param parsed          whether ASM successfully parsed the bytes
 * @param methods         declared methods (name + descriptor)
 * @param invocations     all method call sites
 * @param stringConstants string constants from the constant pool ({@code ldc})
 * @param container       jar-chain this class came from for nested archives
 *                        (e.g. {@code bundled/lib.jar!/}), or {@code ""} for the top-level JAR
 * @param taintFlows      data-flow-confirmed flows from an external source to a dangerous sink
 *                        (e.g. network/decoded bytes reaching {@code defineClass})
 */
public record ClassScan(
        String internalName,
        String superName,
        List<String> interfaces,
        int access,
        boolean parsed,
        List<MethodInfo> methods,
        List<Invocation> invocations,
        List<String> stringConstants,
        String container,
        List<TaintFlow> taintFlows) {

    public String dottedName() {
        return internalName.replace('/', '.');
    }

    /** Human-readable location including the nested jar-chain. */
    public String displayName() {
        String dotted = dottedName();
        return container == null || container.isEmpty() ? dotted : container + dotted;
    }

    /** The nested jar-chain ({@code ""} for the top-level JAR), for finding attribution. */
    public String nestedPath() {
        return container == null || container.isEmpty() ? null : container;
    }
}
