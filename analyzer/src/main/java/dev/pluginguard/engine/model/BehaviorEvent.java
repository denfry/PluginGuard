package dev.pluginguard.engine.model;

/**
 * One behavior the plugin exhibited while running in the sandbox, read back from the container's
 * structured behavior log. Mirrors {@code dev.pluginguard.sandbox.runtime.BehaviorEvent} (the two
 * modules do not share code — the runtime ships inside the isolated image).
 *
 * @param type    event kind (e.g. {@code PROCESS_EXEC}, {@code NETWORK_CONNECT}, {@code REFLECTION})
 * @param target  the concrete operand (command, host:port, class name, path); may be {@code null}
 * @param detail  human-readable note; may be {@code null}
 * @param source  best-effort plugin class/method origin; may be {@code null}
 * @param blocked whether the sandbox actively prevented the action
 */
public record BehaviorEvent(
        String type,
        String target,
        String detail,
        String source,
        boolean blocked) {
}
