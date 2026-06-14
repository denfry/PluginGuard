package dev.pluginguard.engine.analyzers;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.pluginguard.engine.AnalysisContext;
import dev.pluginguard.engine.Analyzer;
import dev.pluginguard.engine.model.ArtifactType;
import dev.pluginguard.engine.model.Category;
import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.ResourceFile;
import dev.pluginguard.engine.model.Severity;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Analyzes the two code-light Minecraft archive kinds.
 *
 * <p><strong>Resource packs</strong> cannot execute code; their realistic risks (a binary disguised
 * as a texture, phishing text, a zip-slip path, a decompression bomb) are already covered by the
 * shared embedded-payload, string-IOC, structure and zip-guard passes. This adds the pack-specific
 * touches: {@code pack.mcmeta} validity and a note about bundled GPU shaders.
 *
 * <p><strong>Data packs</strong> <em>are</em> code-bearing: their {@code .mcfunction} files run server
 * commands. This flags the genuinely dangerous patterns — functions wired to run automatically on
 * load/every tick (auto-execution &amp; persistence), operator-granting commands, self-recursive
 * functions (lag machines), and {@code tellraw} components with clickable external links (phishing).
 */
@Component
@Order(50)
public class PackAnalyzer implements Analyzer {

    private static final ObjectMapper JSON = new ObjectMapper();

    /** {@code data/<ns>/function(s)/<path>.mcfunction}. */
    private static final Pattern FUNCTION_FILE =
            Pattern.compile("(?i)^data/([^/]+)/functions?/(.+)\\.mcfunction$");
    /** The two vanilla auto-run function tags. */
    private static final Pattern AUTORUN_TAG =
            Pattern.compile("(?i)^data/minecraft/tags/functions?/(load|tick)\\.json$");
    /** An {@code op}/{@code deop} command at the start of a line or after {@code run}. */
    private static final Pattern OP_COMMAND =
            Pattern.compile("(?im)(?:^|\\brun\\s+)(?:minecraft:)?(?:de)?op\\b");
    /** Forge of a clickable external link inside a text component (tellraw/title/sign/book). */
    private static final Pattern OPEN_URL = Pattern.compile("(?i)\"open_url\"");

    @Override
    public String name() {
        return "pack";
    }

    @Override
    public void analyze(AnalysisContext ctx) {
        ArtifactType type = ctx.artifactType();
        if (type == ArtifactType.RESOURCE_PACK) {
            analyzeResourcePack(ctx);
        } else if (type == ArtifactType.DATA_PACK) {
            analyzeDataPack(ctx);
        }
    }

    // --- Resource packs ----------------------------------------------------------------------

    private void analyzeResourcePack(AnalysisContext ctx) {
        validatePackMcmeta(ctx, Category.RESOURCE_PACK);

        boolean shaders = ctx.jar().resources().stream().anyMatch(r -> {
            String n = r.name().toLowerCase(Locale.ROOT);
            return n.contains("/shaders/") || n.startsWith("shaders/")
                    || n.endsWith(".fsh") || n.endsWith(".vsh") || n.endsWith(".glsl");
        });
        if (shaders) {
            ctx.add(Finding.builder("RP_SHADERS", Category.RESOURCE_PACK, Severity.INFO)
                    .title("Bundles GPU shaders")
                    .description("The pack ships GLSL shader programs. Shaders run on the GPU, not the JVM, and cannot "
                            + "steal data, but a malformed shader can crash or hang a client's graphics driver.")
                    .recommendation("Informational; only a concern if the pack is otherwise untrusted.")
                    .scoreImpact(0)
                    .build());
        }

        ctx.add(Finding.builder("RESOURCE_PACK_INFO", Category.RESOURCE_PACK, Severity.INFO)
                .title("Artifact is a resource pack")
                .description("Resource packs contain only assets (textures, sounds, models, fonts) and cannot execute "
                        + "code on a client. The remaining risks — a binary disguised as an asset, a zip-slip path, a "
                        + "decompression bomb, or phishing text — are checked by the structure, embedded-payload and "
                        + "string passes; see any findings above.")
                .recommendation("Treat as low risk unless another finding fired.")
                .scoreImpact(0)
                .build());
    }

    // --- Data packs --------------------------------------------------------------------------

    private void analyzeDataPack(AnalysisContext ctx) {
        validatePackMcmeta(ctx, Category.DATA_PACK);

        boolean autorun = false;
        for (ResourceFile res : ctx.jar().resources()) {
            String name = res.name();
            if (AUTORUN_TAG.matcher(name).matches()) {
                autorun = true;
            }
            var fn = FUNCTION_FILE.matcher(name);
            if (fn.matches()) {
                String functionId = fn.group(1) + ":" + fn.group(2);
                scanFunction(ctx, name, functionId, res.text());
            }
        }

        if (autorun) {
            ctx.add(Finding.builder("DP_AUTORUN_TAG", Category.DATA_PACK, Severity.MEDIUM)
                    .title("Runs functions automatically (load/tick)")
                    .description("The pack defines a minecraft:load and/or minecraft:tick function tag, so its functions "
                            + "execute the moment the pack loads and/or every game tick — without anyone running a "
                            + "command. That is how a data pack persists and auto-activates its behaviour.")
                    .recommendation("Read the load/tick functions: they run on their own, so they are where hostile "
                            + "behaviour would live.")
                    .location("data/minecraft/tags/function/")
                    .scoreImpact(12)
                    .build());
        }

        ctx.add(Finding.builder("DATA_PACK_INFO", Category.DATA_PACK, Severity.INFO)
                .title("Artifact is a data pack")
                .description("Data packs run server commands at permission level 2 — they cannot run shell commands or, "
                        + "by default, grant operator, but they can grief the world (fill/clone), force items, lag the "
                        + "server with loops, and show players clickable links. Review the flagged functions.")
                .recommendation("Treat command content as untrusted server logic.")
                .scoreImpact(0)
                .build());
    }

    private void scanFunction(AnalysisContext ctx, String location, String functionId, String text) {
        if (text == null || text.isBlank()) {
            return;
        }
        if (OP_COMMAND.matcher(text).find()) {
            ctx.add(Finding.builder("DP_OP_COMMAND", Category.DATA_PACK, Severity.HIGH)
                    .title("Function grants/removes operator")
                    .description("The function '" + functionId + "' issues an op/deop command. Data packs run below op "
                            + "level by default, so this only works where function permissions were elevated — but where "
                            + "it does, it is a direct privilege-escalation backdoor.")
                    .recommendation("Do not load on a server that raises the function permission level.")
                    .location(location)
                    .evidence("op/deop command")
                    .scoreImpact(20)
                    .build());
        }
        // Direct self-recursion: a function that calls itself loops forever (a lag machine).
        if (Pattern.compile("(?i)function\\s+(minecraft:)?" + Pattern.quote(functionId) + "\\b").matcher(text).find()) {
            ctx.add(Finding.builder("DP_SELF_RECURSION", Category.DATA_PACK, Severity.MEDIUM)
                    .title("Self-recursive function (possible lag machine)")
                    .description("The function '" + functionId + "' calls itself. Unbounded function recursion runs as "
                            + "fast as the server can manage and is the classic way to deliberately lag or freeze a server.")
                    .recommendation("Confirm the recursion terminates (a guard/score check); an unconditional self-call is hostile.")
                    .location(location)
                    .evidence("function " + functionId)
                    .scoreImpact(12)
                    .build());
        }
        if (OPEN_URL.matcher(text).find()) {
            ctx.add(Finding.builder("DP_TELLRAW_LINK", Category.DATA_PACK, Severity.LOW)
                    .title("Shows players a clickable external link")
                    .description("The function '" + functionId + "' builds a text component with a clickable open_url "
                            + "action. Legitimate for info messages, but also used to push players to phishing or "
                            + "scam sites in chat.")
                    .recommendation("Check the destination URL; see the Network summary.")
                    .location(location)
                    .evidence("clickEvent open_url")
                    .scoreImpact(5)
                    .build());
        }
    }

    private void validatePackMcmeta(AnalysisContext ctx, Category category) {
        Optional<ResourceFile> mcmeta = ctx.jar().resource("pack.mcmeta");
        if (mcmeta.isEmpty()) {
            return;
        }
        try {
            JsonNode root = JSON.readTree(mcmeta.get().text());
            if (!root.path("pack").hasNonNull("pack_format")) {
                ctx.add(Finding.builder("PACK_MCMETA_INVALID", category, Severity.LOW)
                        .title("pack.mcmeta is missing pack_format")
                        .description("The pack.mcmeta does not declare pack.pack_format. A real pack needs it to load; "
                                + "its absence suggests a malformed or hand-tampered archive.")
                        .recommendation("Verify the pack is genuine.")
                        .location("pack.mcmeta")
                        .scoreImpact(4)
                        .build());
            }
        } catch (Exception e) {
            ctx.add(Finding.builder("PACK_MCMETA_INVALID", category, Severity.LOW)
                    .title("pack.mcmeta could not be parsed")
                    .description("The pack.mcmeta is present but is not valid JSON.")
                    .recommendation("A malformed descriptor can indicate corruption or tampering.")
                    .location("pack.mcmeta")
                    .scoreImpact(4)
                    .build());
        }
    }
}
