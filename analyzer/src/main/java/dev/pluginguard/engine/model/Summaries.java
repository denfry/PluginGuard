package dev.pluginguard.engine.model;

import java.util.List;

/**
 * Aggregated, de-duplicated views over the findings, rendered as dashboard cards in the UI.
 *
 * @param network      distinct network indicators (hosts, URLs, IPs) referenced by the plugin
 * @param filesystem   distinct filesystem paths the plugin reads or writes
 * @param dependencies bundled libraries detected inside the JAR
 * @param classCount   number of {@code .class} files analyzed
 * @param methodCount  number of methods visited during bytecode analysis
 */
public record Summaries(
        List<String> network,
        List<String> filesystem,
        List<Dependency> dependencies,
        int classCount,
        int methodCount) {
}
