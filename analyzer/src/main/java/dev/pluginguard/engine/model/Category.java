package dev.pluginguard.engine.model;

/**
 * High-level grouping for a {@link Finding}. Used by the UI to bucket findings and to render
 * section summaries (e.g. all {@code NETWORK} findings feed the "Network" card).
 */
public enum Category {
    STRUCTURE(Axis.SECURITY),
    PLUGIN_YML(Axis.SECURITY),
    NETWORK(Axis.SECURITY),
    PROCESS(Axis.SECURITY),
    CLASS_LOADING(Axis.SECURITY),
    NATIVE(Axis.SECURITY),
    FILESYSTEM(Axis.SECURITY),
    CRYPTO(Axis.SECURITY),
    REFLECTION(Axis.SECURITY),
    SCRIPTING(Axis.SECURITY),
    DESERIALIZATION(Axis.SECURITY),
    SYSTEM(Axis.SECURITY),
    OBFUSCATION(Axis.SECURITY),
    STRING_IOC(Axis.SECURITY),
    SUPPLY_CHAIN(Axis.SECURITY),
    COMBO(Axis.SECURITY),
    /** Minecraft platform-specific capabilities (console-command dispatch, op control, session token). */
    MINECRAFT(Axis.SECURITY),
    /** A match against a known malware-family indicator (e.g. fractureiser). */
    MALWARE_SIGNATURE(Axis.SECURITY),
    /** Resource-pack-specific findings (pack.mcmeta, shaders, asset risks). */
    RESOURCE_PACK(Axis.SECURITY),
    /** Data-pack-specific findings (auto-run functions, op commands, lag loops, phishing tellraw). */
    DATA_PACK(Axis.SECURITY),
    PROVENANCE(Axis.SECURITY),
    /** Performance / lag-risk findings (heavy work on the server thread, blocking I/O in hot paths). */
    PERFORMANCE(Axis.PERFORMANCE);

    private final Axis axis;

    Category(Axis axis) {
        this.axis = axis;
    }

    /** The report axis this category contributes to. */
    public Axis axis() {
        return axis;
    }
}
