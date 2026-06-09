package dev.pluginguard.engine.analyzers;

import dev.pluginguard.config.AnalyzerProperties;
import dev.pluginguard.engine.AnalysisContext;
import dev.pluginguard.engine.Analyzer;
import dev.pluginguard.engine.model.Category;
import dev.pluginguard.engine.model.Dependency;
import dev.pluginguard.engine.model.Finding;
import dev.pluginguard.engine.model.Severity;
import dev.pluginguard.engine.supplychain.OsvClient;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Phase&nbsp;2 supply-chain CVE check. Takes the bundled dependencies discovered by the
 * {@link DependencyAnalyzer} (Maven {@code groupId:artifactId} + version from {@code pom.properties})
 * and asks OSV.dev whether any have known vulnerabilities, emitting a finding per advisory with a
 * severity derived from CVSS / GHSA labels and a link to the advisory.
 *
 * <p>Disabled by default (it reaches the network). When a lookup cannot be performed (offline or a
 * network error with no cached answer) the analyzer degrades softly: it records a note so a clean
 * result is never mistaken for "no known CVEs".
 */
@Component
@Order(60)
public class CveAnalyzer implements Analyzer {

    private final AnalyzerProperties.SupplyChain cfg;
    private final OsvClient osv;

    public CveAnalyzer(AnalyzerProperties properties, OsvClient osv) {
        this.cfg = properties.getSupplyChain();
        this.osv = osv;
    }

    @Override
    public String name() {
        return "cve-osv";
    }

    @Override
    public void analyze(AnalysisContext ctx) {
        if (!cfg.isCveEnabled()) {
            return;
        }
        Set<OsvClient.Coordinate> coordinates = collectCoordinates(ctx.dependencies());
        if (coordinates.isEmpty()) {
            return;
        }

        int unavailable = 0;
        for (OsvClient.Coordinate coord : coordinates) {
            OsvClient.QueryOutcome outcome = osv.query(coord);
            if (!outcome.available()) {
                unavailable++;
                continue;
            }
            for (OsvClient.OsvVuln vuln : outcome.vulns()) {
                ctx.add(Finding.builder("CVE_" + vuln.id(), Category.SUPPLY_CHAIN, vuln.severity())
                        .title("Known vulnerability in " + coord.name() + " " + coord.version())
                        .description("Bundled dependency " + coord.name() + ":" + coord.version()
                                + " is affected by " + vuln.id()
                                + (vuln.summary().isBlank() ? "." : ": " + vuln.summary())
                                + " A vulnerable bundled library can be exploited even if the plugin's own code is clean.")
                        .recommendation("Update the plugin to a build that bundles a fixed version. Advisory: " + vuln.url())
                        .location(coord.name() + ":" + coord.version())
                        .evidence(vuln.id())
                        .scoreImpact(impactFor(vuln.severity()))
                        .build());
            }
        }

        if (unavailable > 0) {
            ctx.addNote("CVE lookup was unavailable for " + unavailable + " dependency coordinate(s) "
                    + "(offline or network error); those are not a clean bill of health.");
        }
    }

    /** Maven coordinates with a concrete version, de-duplicated, from descriptor-backed dependencies. */
    private Set<OsvClient.Coordinate> collectCoordinates(List<Dependency> dependencies) {
        Set<OsvClient.Coordinate> out = new LinkedHashSet<>();
        for (Dependency dep : dependencies) {
            String name = dep.name();
            String version = dep.version();
            if (name == null || version == null || version.isBlank() || !name.contains(":")) {
                continue; // need groupId:artifactId + version for a reliable OSV query
            }
            out.add(new OsvClient.Coordinate("Maven", name, version.trim()));
        }
        return out;
    }

    private static int impactFor(Severity severity) {
        return switch (severity) {
            case CRITICAL -> 50;
            case HIGH -> 30;
            case MEDIUM -> 15;
            case LOW -> 6;
            case INFO -> 0;
        };
    }
}
