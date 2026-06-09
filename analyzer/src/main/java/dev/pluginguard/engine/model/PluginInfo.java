package dev.pluginguard.engine.model;

import java.util.List;

/**
 * Metadata extracted from {@code plugin.yml} / {@code paper-plugin.yml} / {@code bungee.yml}.
 * All fields may be empty when the descriptor is missing or partial.
 *
 * @param descriptorFile name of the descriptor the data came from (e.g. {@code plugin.yml})
 * @param name           declared plugin name
 * @param version        declared version
 * @param main           main class (fully-qualified)
 * @param apiVersion     declared {@code api-version} (e.g. {@code 1.21}); {@code null} if absent
 * @param authors        declared authors
 * @param commands       declared command names (without leading slash)
 * @param permissions    declared permission nodes
 * @param depend         hard dependencies
 * @param softDepend     soft dependencies
 * @param libraries      runtime libraries pulled from Maven (Paper {@code libraries:} block)
 */
public record PluginInfo(
        String descriptorFile,
        String name,
        String version,
        String main,
        String apiVersion,
        List<String> authors,
        List<String> commands,
        List<String> permissions,
        List<String> depend,
        List<String> softDepend,
        List<String> libraries) {
}
