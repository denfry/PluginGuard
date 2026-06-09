package dev.pluginguard.engine.analyzers;

import dev.pluginguard.engine.AnalysisContext;
import dev.pluginguard.engine.Analyzer;
import dev.pluginguard.engine.model.Category;
import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.PluginInfo;
import dev.pluginguard.engine.model.ResourceFile;
import dev.pluginguard.engine.model.Severity;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Parses the plugin descriptor ({@code plugin.yml} / {@code paper-plugin.yml} / {@code bungee.yml})
 * with SnakeYAML in <strong>safe mode</strong> (no arbitrary type construction) and validates it:
 * missing descriptor, main class that isn't in the JAR, missing api-version, wildcard permissions
 * and backdoor-style command names.
 */
@Component
@Order(20)
public class PluginYmlAnalyzer implements Analyzer {

    private static final Set<String> HIGH_RISK_COMMANDS = Set.of(
            "shell", "exec", "eval", "rce", "backdoor", "runcmd", "syscmd");
    private static final Set<String> SUSPICIOUS_COMMANDS = Set.of(
            "op", "opme", "forceop", "deop", "sudo", "console");

    @Override
    public String name() {
        return "plugin-descriptor";
    }

    @Override
    public void analyze(AnalysisContext ctx) {
        detectPlatform(ctx);

        Optional<ResourceFile> descriptor = firstPresent(ctx, "plugin.yml", "paper-plugin.yml", "bungee.yml");
        if (descriptor.isEmpty()) {
            ctx.add(Finding.builder("YML_MISSING", Category.PLUGIN_YML, Severity.MEDIUM)
                    .title("No plugin descriptor found")
                    .description("No plugin.yml / paper-plugin.yml / bungee.yml was found. A Bukkit/Paper/Bungee "
                            + "plugin cannot load without one, so this file may not be a normal plugin (or it hides it).")
                    .recommendation("Confirm what kind of file this is before installing it.")
                    .scoreImpact(10)
                    .build());
            return;
        }

        ResourceFile file = descriptor.get();
        Map<String, Object> root = parseYaml(file.text());
        if (root == null) {
            ctx.add(Finding.builder("YML_UNPARSEABLE", Category.PLUGIN_YML, Severity.MEDIUM)
                    .title("Plugin descriptor could not be parsed")
                    .description("The " + file.name() + " is present but is not valid YAML.")
                    .recommendation("A malformed descriptor can indicate corruption or tampering.")
                    .location(file.name())
                    .scoreImpact(8)
                    .build());
            return;
        }

        String name = asString(root.get("name"));
        String version = asString(root.get("version"));
        String main = asString(root.get("main"));
        String apiVersion = asString(root.get("api-version"));
        String load = asString(root.get("load"));
        List<String> authors = mergeAuthors(root);
        List<String> commands = mapKeys(root.get("commands"));
        List<String> permissions = mapKeys(root.get("permissions"));
        List<String> depend = asStringList(root.get("depend"));
        List<String> softDepend = asStringList(root.get("softdepend"));
        List<String> loadBefore = asStringList(root.get("loadbefore"));
        List<String> libraries = asStringList(root.get("libraries"));

        ctx.setPluginInfo(new PluginInfo(file.name(), name, version, main, apiVersion,
                authors, commands, permissions, depend, softDepend, libraries));

        checkLoadOrder(ctx, file.name(), load, loadBefore);
        checkLibraries(ctx, file.name(), libraries);
        checkDependencyCount(ctx, file.name(), depend, softDepend);

        // Main class must exist in the JAR.
        if (main != null && !main.isBlank()) {
            String internal = main.replace('.', '/');
            boolean present = ctx.jar().classes().stream()
                    .anyMatch(c -> c.internalName().equals(internal));
            if (!present) {
                ctx.add(Finding.builder("YML_MAIN_MISSING", Category.PLUGIN_YML, Severity.HIGH)
                        .title("Declared main class is missing")
                        .description("The descriptor names main class '" + main + "', but that class is not in the JAR. "
                                + "The plugin would fail to load — or the descriptor was tampered with.")
                        .recommendation("Do not trust a plugin whose declared entry point is absent.")
                        .location(file.name())
                        .evidence(main)
                        .scoreImpact(15)
                        .build());
            }
        }

        // api-version helps the server apply the right compatibility behaviour; absence is a minor smell.
        if ("plugin.yml".equals(file.name()) && (apiVersion == null || apiVersion.isBlank())) {
            ctx.add(Finding.builder("YML_NO_API_VERSION", Category.PLUGIN_YML, Severity.LOW)
                    .title("No api-version declared")
                    .description("plugin.yml does not declare an api-version. Modern plugins should set one.")
                    .recommendation("Minor issue; common in older plugins.")
                    .location(file.name())
                    .scoreImpact(3)
                    .build());
        }

        // Wildcard permissions.
        for (String perm : permissions) {
            if (perm.equals("*") || perm.endsWith(".*")) {
                ctx.add(Finding.builder("YML_WILDCARD_PERMISSION", Category.PLUGIN_YML, Severity.LOW)
                        .title("Broad wildcard permission")
                        .description("Permission '" + perm + "' is a wildcard that can implicitly grant many child nodes.")
                        .recommendation("Wildcards can grant more access than expected; review which nodes they cover.")
                        .location(file.name())
                        .evidence(perm)
                        .scoreImpact(5)
                        .build());
            }
        }

        // Backdoor-style command names.
        for (String cmd : commands) {
            String c = cmd.toLowerCase(Locale.ROOT);
            if (HIGH_RISK_COMMANDS.contains(c)) {
                ctx.add(Finding.builder("YML_BACKDOOR_COMMAND", Category.PLUGIN_YML, Severity.HIGH)
                        .title("Command name suggests command execution")
                        .description("Command '/" + cmd + "' has a name commonly used by backdoors to run shell or "
                                + "arbitrary code.")
                        .recommendation("Inspect what this command does before installing.")
                        .location(file.name())
                        .evidence("/" + cmd)
                        .scoreImpact(20)
                        .build());
            } else if (SUSPICIOUS_COMMANDS.contains(c)) {
                ctx.add(Finding.builder("YML_PRIVILEGE_COMMAND", Category.PLUGIN_YML, Severity.MEDIUM)
                        .title("Command can change operator status")
                        .description("Command '/" + cmd + "' relates to granting operator/console privileges.")
                        .recommendation("Legitimate for admin tools, but confirm it is gated behind permissions.")
                        .location(file.name())
                        .evidence("/" + cmd)
                        .scoreImpact(8)
                        .build());
            }
        }
    }

    /** A plugin that loads at STARTUP or forces itself ahead of others can pre-empt security plugins. */
    private void checkLoadOrder(AnalysisContext ctx, String file, String load, List<String> loadBefore) {
        if (load != null && load.equalsIgnoreCase("STARTUP")) {
            ctx.add(Finding.builder("YML_LOAD_STARTUP", Category.PLUGIN_YML, Severity.LOW)
                    .title("Loads at server STARTUP")
                    .description("The descriptor declares 'load: STARTUP', so the plugin initialises very early in the "
                            + "server lifecycle — before worlds load. Legitimate for some integrations, but it also "
                            + "lets a plugin run before other safeguards are active.")
                    .recommendation("Confirm the plugin genuinely needs to load at startup.")
                    .location(file).evidence("load: STARTUP").scoreImpact(4).build());
        }
        if (!loadBefore.isEmpty()) {
            ctx.add(Finding.builder("YML_LOADBEFORE", Category.PLUGIN_YML, Severity.LOW)
                    .title("Forces itself to load before other plugins")
                    .description("The descriptor uses 'loadbefore' (" + String.join(", ", loadBefore) + ") to force this "
                            + "plugin ahead of others in load order. This can be used to get in front of logging or "
                            + "anti-cheat/security plugins.")
                    .recommendation("Check which plugins it inserts itself before and why.")
                    .location(file).evidence("loadbefore: " + String.join(", ", loadBefore)).scoreImpact(4).build());
        }
    }

    /** Paper {@code libraries:} are fetched from a remote Maven repo at runtime — a supply-chain hop. */
    private void checkLibraries(AnalysisContext ctx, String file, List<String> libraries) {
        if (libraries.isEmpty()) {
            return;
        }
        ctx.add(Finding.builder("YML_REMOTE_LIBRARIES", Category.SUPPLY_CHAIN, Severity.LOW)
                .title("Downloads libraries from a remote repository")
                .description("The descriptor lists " + libraries.size() + " runtime library coordinate(s) in 'libraries:' ("
                        + String.join(", ", libraries) + "). Paper resolves these from a remote Maven repository at "
                        + "load time, so code that is not in this JAR is pulled in at runtime.")
                .recommendation("Make sure each coordinate (and its version) is one you trust; pin versions.")
                .location(file).evidence(String.join(", ", libraries)).scoreImpact(6).build());
    }

    private void checkDependencyCount(AnalysisContext ctx, String file, List<String> depend, List<String> softDepend) {
        int total = depend.size() + softDepend.size();
        if (total > 12) {
            ctx.add(Finding.builder("YML_MANY_DEPENDENCIES", Category.PLUGIN_YML, Severity.INFO)
                    .title("Unusually many declared dependencies")
                    .description("The descriptor declares " + total + " hard/soft dependencies. A very large dependency "
                            + "list can be a way to hook into many other plugins; usually it is just a feature-rich plugin.")
                    .recommendation("Informational — review only if other findings are present.")
                    .location(file).evidence(total + " dependencies").scoreImpact(0).build());
        }
    }

    private void detectPlatform(AnalysisContext ctx) {
        if (hasResource(ctx, "velocity-plugin.json")) {
            ctx.setPlatform("Velocity");
        } else if (hasResource(ctx, "bungee.yml")) {
            ctx.setPlatform("BungeeCord");
        } else if (hasResource(ctx, "paper-plugin.yml")) {
            ctx.setPlatform("Paper");
        } else if (hasResource(ctx, "plugin.yml")) {
            ctx.setPlatform("Bukkit/Spigot/Paper");
        } else {
            ctx.setPlatform("Unknown");
        }
    }

    private boolean hasResource(AnalysisContext ctx, String name) {
        return ctx.jar().resource(name).isPresent();
    }

    private Optional<ResourceFile> firstPresent(AnalysisContext ctx, String... names) {
        for (String n : names) {
            Optional<ResourceFile> r = ctx.jar().resource(n);
            if (r.isPresent()) {
                return r;
            }
        }
        return Optional.empty();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> parseYaml(String text) {
        try {
            LoaderOptions options = new LoaderOptions();
            options.setMaxAliasesForCollections(50);
            Yaml yaml = new Yaml(new SafeConstructor(options));
            Object loaded = yaml.load(text);
            return (loaded instanceof Map) ? (Map<String, Object>) loaded : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    private List<String> mergeAuthors(Map<String, Object> root) {
        Set<String> authors = new LinkedHashSet<>(asStringList(root.get("authors")));
        String single = asString(root.get("author"));
        if (single != null && !single.isBlank()) {
            authors.add(single);
        }
        return new ArrayList<>(authors);
    }

    private static String asString(Object o) {
        return o == null ? null : String.valueOf(o);
    }

    @SuppressWarnings("unchecked")
    private static List<String> asStringList(Object o) {
        if (o == null) {
            return List.of();
        }
        if (o instanceof List<?> list) {
            List<String> out = new ArrayList<>();
            for (Object item : list) {
                if (item != null) {
                    out.add(String.valueOf(item));
                }
            }
            return out;
        }
        if (o instanceof String s) {
            return Arrays.stream(s.split(",")).map(String::trim).filter(v -> !v.isBlank()).toList();
        }
        return List.of(String.valueOf(o));
    }

    @SuppressWarnings("unchecked")
    private static List<String> mapKeys(Object o) {
        if (o instanceof Map<?, ?> map) {
            List<String> keys = new ArrayList<>();
            for (Object k : map.keySet()) {
                keys.add(String.valueOf(k));
            }
            return keys;
        }
        return List.of();
    }
}
