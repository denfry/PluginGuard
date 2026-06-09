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
    SYSTEM,
    OBFUSCATION,
    STRING_IOC,
    PROVENANCE
}
