package dev.pluginguard.engine.model;

/**
 * The kind of Minecraft artifact an upload was identified as. PluginGuard started as a
 * server-plugin scanner but also analyzes mods, resource packs and data packs; the analysis
 * pipeline branches on this so, for example, a Forge mod is not mis-flagged for lacking a
 * {@code plugin.yml}, and a resource pack is judged by pack-specific rules.
 *
 * <p>Detected by {@code LoaderDetector} from the descriptors/structure present in the archive.
 */
public enum ArtifactType {
    PLUGIN_BUKKIT(Family.PLUGIN, "Bukkit/Spigot/Paper"),
    PLUGIN_BUNGEE(Family.PLUGIN, "BungeeCord"),
    PLUGIN_VELOCITY(Family.PLUGIN, "Velocity"),
    MOD_FORGE(Family.MOD, "Forge"),
    MOD_NEOFORGE(Family.MOD, "NeoForge"),
    MOD_FABRIC(Family.MOD, "Fabric"),
    MOD_QUILT(Family.MOD, "Quilt"),
    RESOURCE_PACK(Family.PACK, "Resource pack"),
    DATA_PACK(Family.PACK, "Data pack"),
    UNKNOWN(Family.UNKNOWN, "Unknown");

    /** Coarse grouping used for honest, family-wide caveats (e.g. "mods get static analysis only"). */
    public enum Family { PLUGIN, MOD, PACK, UNKNOWN }

    private final Family family;
    private final String label;

    ArtifactType(Family family, String label) {
        this.family = family;
        this.label = label;
    }

    public Family family() {
        return family;
    }

    /** Human-readable platform label shown in the report (also the legacy {@code platform} string). */
    public String label() {
        return label;
    }

    public boolean isPlugin() {
        return family == Family.PLUGIN;
    }

    public boolean isMod() {
        return family == Family.MOD;
    }

    public boolean isPack() {
        return family == Family.PACK;
    }
}
