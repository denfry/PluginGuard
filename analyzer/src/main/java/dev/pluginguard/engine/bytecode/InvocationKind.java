package dev.pluginguard.engine.bytecode;

/** How a call site was observed during the ASM pass. */
public enum InvocationKind {
    /** Ordinary {@code invokevirtual/static/special/interface}. */
    INVOKE,
    /** An {@code invokedynamic} bootstrap method or one of its method-handle arguments. */
    INVOKE_DYNAMIC,
    /** A target resolved from reflection string operands (e.g. {@code Class.forName("...")}). */
    REFLECTIVE
}
