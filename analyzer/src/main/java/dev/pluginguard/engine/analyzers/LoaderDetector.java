package dev.pluginguard.engine.analyzers;

import dev.pluginguard.engine.AnalysisContext;
import dev.pluginguard.engine.Analyzer;
import dev.pluginguard.engine.model.ArtifactType;
import dev.pluginguard.engine.model.JarEntryInfo;
import dev.pluginguard.engine.model.JarModel;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.Locale;

/**
 * Runs first and classifies the upload into an {@link ArtifactType} from the descriptors and layout
 * present in the archive, then records it (and the human-readable platform label) on the context.
 * Later analyzers branch on it — e.g. a Forge mod is not flagged for missing a {@code plugin.yml},
 * and resource/data packs are judged by their own rules instead of the bytecode table.
 *
 * <p>Detection is descriptor-first (the loader manifests are authoritative) with a structural
 * fallback for packs ({@code pack.mcmeta} plus a {@code data/} vs {@code assets/} top-level tree).
 */
@Component
@Order(5)
public class LoaderDetector implements Analyzer {

    @Override
    public String name() {
        return "loader-detection";
    }

    @Override
    public void analyze(AnalysisContext ctx) {
        ArtifactType type = detect(ctx.jar());
        ctx.setArtifactType(type);
        ctx.setPlatform(type.label());
    }

    private ArtifactType detect(JarModel jar) {
        if (!jar.validZip()) {
            return ArtifactType.UNKNOWN;
        }

        // --- Server-plugin descriptors (authoritative) ---
        if (has(jar, "velocity-plugin.json")) {
            return ArtifactType.PLUGIN_VELOCITY;
        }
        if (has(jar, "bungee.yml")) {
            return ArtifactType.PLUGIN_BUNGEE;
        }
        if (has(jar, "plugin.yml") || has(jar, "paper-plugin.yml")) {
            return ArtifactType.PLUGIN_BUKKIT;
        }

        // --- Mod-loader descriptors --- (NeoForge before Forge: a jar may ship both for cross-loading.)
        if (has(jar, "META-INF/neoforge.mods.toml")) {
            return ArtifactType.MOD_NEOFORGE;
        }
        if (has(jar, "META-INF/mods.toml")) {
            return ArtifactType.MOD_FORGE;
        }
        if (has(jar, "quilt.mod.json")) {
            return ArtifactType.MOD_QUILT;
        }
        if (has(jar, "fabric.mod.json")) {
            return ArtifactType.MOD_FABRIC;
        }

        // --- Packs: pack.mcmeta plus a data/ (functions) or assets/ (textures) top-level tree. ---
        if (has(jar, "pack.mcmeta")) {
            return hasTopLevelDir(jar, "data/") ? ArtifactType.DATA_PACK : ArtifactType.RESOURCE_PACK;
        }

        return ArtifactType.UNKNOWN;
    }

    private static boolean has(JarModel jar, String resourceName) {
        return jar.resource(resourceName).isPresent();
    }

    /** True if any top-level entry sits under {@code prefix} (e.g. {@code data/}); nested-jar entries are ignored. */
    private static boolean hasTopLevelDir(JarModel jar, String prefix) {
        for (JarEntryInfo entry : jar.entries()) {
            String name = entry.name().toLowerCase(Locale.ROOT);
            if (!name.contains("!/") && name.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }
}
