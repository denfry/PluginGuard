package dev.pluginguard.engine.model;

/**
 * High-level grouping for a {@link Finding}. Used by the UI to bucket findings and to render
 * section summaries (e.g. all {@code NETWORK} findings feed the "Network" card).
 */
public enum Category {
    STRUCTURE,
    PLUGIN_YML,
    NETWORK,
    PROCESS,
    CLASS_LOADING,
    NATIVE,
    FILESYSTEM,
    CRYPTO,
    REFLECTION,
    SCRIPTING,
    DESERIALIZATION,
    SYSTEM,
    OBFUSCATION,
    STRING_IOC,
    SUPPLY_CHAIN,
    COMBO,
    /** Minecraft platform-specific capabilities (console-command dispatch, op control, session token). */
    MINECRAFT,
    /** A match against a known malware-family indicator (e.g. fractureiser). */
    MALWARE_SIGNATURE,
    /** Resource-pack-specific findings (pack.mcmeta, shaders, asset risks). */
    RESOURCE_PACK,
    /** Data-pack-specific findings (auto-run functions, op commands, lag loops, phishing tellraw). */
    DATA_PACK,
    PROVENANCE
}
