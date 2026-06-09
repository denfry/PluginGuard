package dev.pluginguard.engine.bytecode;

import java.util.Set;

/**
 * Classifies {@code invokedynamic} bootstrap owners. The JDK's own factories (lambdas, string
 * concatenation, records, pattern-matching switches) are emitted by every modern compiler; any
 * other bootstrap is an unusual, obfuscator-style construct. Shared by the bytecode and
 * obfuscation analyzers so both classify call sites identically.
 */
public final class IndyBootstraps {

    private static final Set<String> BENIGN = Set.of(
            "java/lang/invoke/LambdaMetafactory",
            "java/lang/invoke/StringConcatFactory",
            "java/lang/runtime/ObjectMethods",
            "java/lang/runtime/SwitchBootstraps");

    private IndyBootstraps() {
    }

    /** Whether this bootstrap owner (internal name) is one of the standard JDK factories. */
    public static boolean isBenign(String ownerInternalName) {
        return BENIGN.contains(ownerInternalName);
    }

    /** A custom (non-JDK) bootstrap on an invokedynamic call site — an obfuscation signal. */
    public static boolean isCustom(Invocation inv) {
        return inv.kind() == InvocationKind.INVOKE_DYNAMIC && !isBenign(inv.owner());
    }
}
