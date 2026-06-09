package dev.pluginguard.engine.bytecode;

/**
 * A method call site captured during the single ASM pass.
 *
 * @param owner         internal name of the declaring type, e.g. {@code java/lang/Runtime}
 * @param name          method name, e.g. {@code exec} or {@code <init>} for constructors
 * @param descriptor    method descriptor
 * @param callerClass   internal name of the class containing the call
 * @param callerMethod  name of the method containing the call (for report locations)
 * @param kind          how the call site was observed (plain invoke, invokedynamic, resolved reflection)
 * @param stringOperand the nearest preceding string constant pushed before the call, if any
 *                      (used to resolve {@code Class.forName("...")} / {@code getMethod("...")}); may be {@code null}
 */
public record Invocation(String owner, String name, String descriptor,
                         String callerClass, String callerMethod,
                         InvocationKind kind, String stringOperand) {

    /** Backwards-compatible factory for a plain invoke with no captured string operand. */
    public Invocation(String owner, String name, String descriptor,
                      String callerClass, String callerMethod) {
        this(owner, name, descriptor, callerClass, callerMethod, InvocationKind.INVOKE, null);
    }

    public String ownerDotted() {
        return owner.replace('/', '.');
    }

    public boolean isDynamic() {
        return kind == InvocationKind.INVOKE_DYNAMIC;
    }
}
