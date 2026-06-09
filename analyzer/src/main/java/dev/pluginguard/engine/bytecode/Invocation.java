package dev.pluginguard.engine.bytecode;

/**
 * A method call site captured during the single ASM pass.
 *
 * @param owner        internal name of the declaring type, e.g. {@code java/lang/Runtime}
 * @param name         method name, e.g. {@code exec} or {@code <init>} for constructors
 * @param descriptor   method descriptor
 * @param callerClass  internal name of the class containing the call
 * @param callerMethod name of the method containing the call (for report locations)
 */
public record Invocation(String owner, String name, String descriptor,
                         String callerClass, String callerMethod) {

    public String ownerDotted() {
        return owner.replace('/', '.');
    }
}
