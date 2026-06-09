package dev.pluginguard.sandbox.runtime;

/**
 * Thrown when the sandbox actively blocks a dangerous action the plugin attempted (process launch,
 * outbound connection, file write, {@code System.exit}, …). It extends {@link SecurityException} so
 * it propagates through the same paths the JDK uses for access denials.
 */
public class SandboxBlockedException extends SecurityException {

    public SandboxBlockedException(String message) {
        super(message);
    }
}
