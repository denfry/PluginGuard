package dev.pluginguard.engine.model;

/**
 * A {@code .class} entry and its raw bytes. {@code internalName} is the JVM internal name
 * (slash-separated, no {@code .class} suffix), e.g. {@code dev/pluginguard/Foo}.
 */
public record ClassFile(String internalName, byte[] bytes) {

    /** Dotted, human-readable class name, e.g. {@code dev.pluginguard.Foo}. */
    public String dottedName() {
        return internalName.replace('/', '.');
    }
}
