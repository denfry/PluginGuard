package dev.pluginguard.engine.analyzers;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.pluginguard.engine.AnalysisContext;
import dev.pluginguard.engine.Analyzer;
import dev.pluginguard.engine.bytecode.ClassScan;
import dev.pluginguard.engine.model.ArtifactType;
import dev.pluginguard.engine.model.Category;
import dev.pluginguard.engine.model.Dependency;
import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.PluginInfo;
import dev.pluginguard.engine.model.ResourceFile;
import dev.pluginguard.engine.model.Severity;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Validates mod artifacts (Forge/NeoForge {@code mods.toml}, Fabric {@code fabric.mod.json}, Quilt
 * {@code quilt.mod.json}) and surfaces mod-specific risks the generic bytecode table cannot express:
 * a class that registers itself as a raw <em>coremod / class transformer</em> (it can rewrite any
 * game or mod class at load time — agent-level power) and access-wideners that open up engine
 * internals. The parsed descriptor is folded into the same {@link PluginInfo} the UI already renders.
 *
 * <p>All parsing is read-only and tolerant: a malformed descriptor is noted, never fatal.
 */
@Component
@Order(22)
public class ModAnalyzer implements Analyzer {

    private static final ObjectMapper JSON = new ObjectMapper();

    /**
     * Interfaces whose implementation means the mod registers a <em>raw</em> bytecode transformer or
     * coremod — it can rewrite arbitrary classes at load time, outside Mixin's declarative model.
     */
    private static final Set<String> COREMOD_TRANSFORMER_TYPES = Set.of(
            "net/minecraftforge/fml/relauncher/IFMLLoadingPlugin",      // legacy Forge coremod
            "net/minecraft/launchwrapper/IClassTransformer",            // legacy launchwrapper transformer
            "cpw/mods/modlauncher/api/ITransformationService",          // modern modlauncher service
            "cpw/mods/modlauncher/api/ITransformer");                   // modern modlauncher transformer

    /** Programmatic control over which Mixins apply — legitimate but powerful, so worth noting. */
    private static final String MIXIN_CONFIG_PLUGIN = "org/spongepowered/asm/mixin/extensibility/IMixinConfigPlugin";

    private static final Pattern TOML_VALUE = Pattern.compile("\"([^\"]*)\"");

    @Override
    public String name() {
        return "mod-descriptor";
    }

    @Override
    public void analyze(AnalysisContext ctx) {
        ArtifactType type = ctx.artifactType();
        if (!type.isMod()) {
            return;
        }

        switch (type) {
            case MOD_FABRIC -> parseFabric(ctx, "fabric.mod.json");
            case MOD_QUILT -> parseQuilt(ctx, "quilt.mod.json");
            case MOD_FORGE -> parseToml(ctx, "META-INF/mods.toml");
            case MOD_NEOFORGE -> parseToml(ctx, "META-INF/neoforge.mods.toml");
            default -> { /* not a mod */ }
        }

        detectCoremodTransformers(ctx);
    }

    // --- Fabric / Quilt (JSON) ---------------------------------------------------------------

    private void parseFabric(AnalysisContext ctx, String file) {
        JsonNode root = readJson(ctx, file);
        if (root == null) {
            return;
        }
        String id = text(root, "id");
        String name = firstNonBlank(text(root, "name"), id);
        String version = text(root, "version");
        List<String> authors = jsonAuthors(root.get("authors"));
        String main = firstEntrypoint(root.get("entrypoints"));
        List<String> depends = jsonKeys(root.get("depends"));

        setModInfo(ctx, file, name, version, main, authors, depends);
        addDependencies(ctx, depends, file);

        if (root.hasNonNull("accessWidener")) {
            accessWidenerFinding(ctx, file, text(root, "accessWidener"));
        }
    }

    private void parseQuilt(AnalysisContext ctx, String file) {
        JsonNode root = readJson(ctx, file);
        if (root == null) {
            return;
        }
        JsonNode loader = root.path("quilt_loader");
        String id = text(loader, "id");
        String version = text(loader, "version");
        String name = firstNonBlank(text(loader.path("metadata"), "name"), id);
        List<String> depends = quiltDepends(loader.get("depends"));
        String main = firstEntrypoint(loader.get("entrypoints"));

        setModInfo(ctx, file, name, version, main, List.of(), depends);
        addDependencies(ctx, depends, file);

        if (root.hasNonNull("access_widener")) {
            accessWidenerFinding(ctx, file, text(root, "access_widener"));
        }
    }

    // --- Forge / NeoForge (TOML) -------------------------------------------------------------

    private void parseToml(AnalysisContext ctx, String file) {
        Optional<ResourceFile> res = ctx.jar().resource(file);
        if (res.isEmpty()) {
            return;
        }
        String text = res.get().text();
        String modId = tomlValue(text, "modId");
        String name = firstNonBlank(tomlValue(text, "displayName"), modId);
        String version = tomlValue(text, "version");
        String authors = tomlValue(text, "authors");
        List<String> authorList = authors == null ? List.of() : List.of(authors);

        setModInfo(ctx, file, name, version, modId, authorList, List.of());
    }

    // --- Coremod / transformer detection (bytecode-level) ------------------------------------

    private void detectCoremodTransformers(AnalysisContext ctx) {
        Set<String> seen = new LinkedHashSet<>();
        for (ClassScan scan : ctx.classScans()) {
            List<String> supertypes = new ArrayList<>(scan.interfaces());
            if (scan.superName() != null) {
                supertypes.add(scan.superName());
            }
            for (String t : supertypes) {
                if (COREMOD_TRANSFORMER_TYPES.contains(t) && seen.add(scan.displayName() + "|coremod")) {
                    ctx.add(Finding.builder("MOD_COREMOD_TRANSFORMER", Category.MINECRAFT, Severity.HIGH)
                            .title("Registers a coremod / class transformer")
                            .description("The class implements " + t.replace('/', '.') + ", a coremod/transformer hook "
                                    + "that rewrites other classes' bytecode as the game loads. This is agent-level "
                                    + "power — it can silently modify the game, other mods, or anti-cheat — and is far "
                                    + "rarer and riskier than ordinary (declarative) Mixins.")
                            .recommendation("Confirm the mod genuinely needs raw bytecode transformation and review what it rewrites.")
                            .location(scan.displayName())
                            .evidence(t.replace('/', '.'))
                            .nestedPath(scan.nestedPath())
                            .scoreImpact(24)
                            .build());
                } else if (t.equals(MIXIN_CONFIG_PLUGIN) && seen.add(scan.displayName() + "|mixinplugin")) {
                    ctx.add(Finding.builder("MOD_MIXIN_CONFIG_PLUGIN", Category.MINECRAFT, Severity.MEDIUM)
                            .title("Programmatically controls Mixin application")
                            .description("The class implements IMixinConfigPlugin, which lets the mod decide at runtime "
                                    + "which Mixins to apply and rewrite their targets. Legitimate for advanced mods, but "
                                    + "it can also be used to hide or conditionally activate code injection.")
                            .recommendation("Review the plugin's shouldApplyMixin / preApply logic if other risks are present.")
                            .location(scan.displayName())
                            .evidence("IMixinConfigPlugin")
                            .nestedPath(scan.nestedPath())
                            .scoreImpact(12)
                            .build());
                }
            }
        }
    }

    // --- shared helpers ----------------------------------------------------------------------

    private void setModInfo(AnalysisContext ctx, String file, String name, String version,
                            String main, List<String> authors, List<String> depends) {
        ctx.setPluginInfo(new PluginInfo(file, name, version, main, null,
                authors, List.of(), List.of(), depends, List.of(), List.of()));
    }

    private void addDependencies(AnalysisContext ctx, List<String> depends, String file) {
        for (String d : depends) {
            ctx.addDependency(new Dependency(d, null, file));
        }
    }

    private void accessWidenerFinding(AnalysisContext ctx, String file, String widener) {
        ctx.add(Finding.builder("MOD_ACCESS_WIDENER", Category.MINECRAFT, Severity.LOW)
                .title("Uses an access widener")
                .description("The mod declares an access widener (" + widener + "), which opens up private/final game "
                        + "internals so the mod can touch them. Common for deep mods, but it widens the attack surface.")
                .recommendation("Informational; review only if the mod shows other risky behaviour.")
                .location(file)
                .evidence(widener)
                .scoreImpact(3)
                .build());
    }

    private JsonNode readJson(AnalysisContext ctx, String file) {
        Optional<ResourceFile> res = ctx.jar().resource(file);
        if (res.isEmpty()) {
            return null;
        }
        try {
            return JSON.readTree(res.get().text());
        } catch (Exception e) {
            ctx.add(Finding.builder("MOD_DESCRIPTOR_UNPARSEABLE", Category.MINECRAFT, Severity.LOW)
                    .title("Mod descriptor could not be parsed")
                    .description("The " + file + " is present but is not valid JSON.")
                    .recommendation("A malformed descriptor can indicate corruption or tampering.")
                    .location(file)
                    .scoreImpact(6)
                    .build());
            return null;
        }
    }

    private static String tomlValue(String text, String key) {
        Matcher m = Pattern.compile("(?m)^\\s*" + Pattern.quote(key) + "\\s*=\\s*(.*)$").matcher(text);
        if (m.find()) {
            Matcher v = TOML_VALUE.matcher(m.group(1));
            if (v.find()) {
                return v.group(1);
            }
        }
        return null;
    }

    private static String text(JsonNode node, String field) {
        if (node == null) {
            return null;
        }
        JsonNode v = node.get(field);
        return v != null && v.isValueNode() ? v.asText() : null;
    }

    /** Fabric authors: an array of plain strings or of objects with a {@code name} field. */
    private static List<String> jsonAuthors(JsonNode authors) {
        if (authors == null || !authors.isArray()) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        for (JsonNode a : authors) {
            if (a.isTextual()) {
                out.add(a.asText());
            } else if (a.isObject() && a.hasNonNull("name")) {
                out.add(a.get("name").asText());
            }
        }
        return out;
    }

    /** Keys of a JSON object (e.g. Fabric {@code depends: {"fabricloader": "*", ...}}). */
    private static List<String> jsonKeys(JsonNode obj) {
        if (obj == null || !obj.isObject()) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        for (Map.Entry<String, JsonNode> e : obj.properties()) {
            out.add(e.getKey());
        }
        return out;
    }

    /** Quilt {@code depends}: an array of strings or of objects with an {@code id} field. */
    private static List<String> quiltDepends(JsonNode depends) {
        if (depends == null || !depends.isArray()) {
            return List.of();
        }
        List<String> out = new ArrayList<>();
        for (JsonNode d : depends) {
            if (d.isTextual()) {
                out.add(d.asText());
            } else if (d.isObject() && d.hasNonNull("id")) {
                out.add(d.get("id").asText());
            }
        }
        return out;
    }

    /** First entrypoint class across all entrypoint groups (values may be strings or {@code {value: "..."}}). */
    private static String firstEntrypoint(JsonNode entrypoints) {
        if (entrypoints == null || !entrypoints.isObject()) {
            return null;
        }
        for (Map.Entry<String, JsonNode> entry : entrypoints.properties()) {
            JsonNode group = entry.getValue();
            if (group.isArray()) {
                for (JsonNode e : group) {
                    if (e.isTextual()) {
                        return e.asText();
                    }
                    if (e.isObject() && e.hasNonNull("value")) {
                        return e.get("value").asText();
                    }
                }
            }
        }
        return null;
    }

    private static String firstNonBlank(String a, String b) {
        return a != null && !a.isBlank() ? a : b;
    }
}
