package dev.pluginguard.engine.model;

/**
 * A {@code .class} entry and its raw bytes. {@code internalName} is the JVM internal name
 * (slash-separated, no {@code .class} suffix), e.g. {@code dev/pluginguard/Foo}.
 *
 * @param internalName JVM internal name
 * @param bytes        raw class bytes (never loaded or executed)
 * @param container    jar-chain this class came from for nested archives
 *                     (e.g. {@code bundled/lib.jar!/}), or {@code ""} for the top-level JAR
 */
public record ClassFile(String internalName, byte[] bytes, String container) {

    public ClassFile(String internalName, byte[] bytes) {
        this(internalName, bytes, "");
    }

    /** Dotted, human-readable class name, e.g. {@code dev.pluginguard.Foo}. */
    public String dottedName() {
        return internalName.replace('/', '.');
    }

    /** Human-readable location including the nested jar-chain, e.g. {@code lib.jar!/dev.pluginguard.Foo}. */
    public String displayName() {
        String dotted = dottedName();
        return container == null || container.isEmpty() ? dotted : container + dotted;
    }
}
