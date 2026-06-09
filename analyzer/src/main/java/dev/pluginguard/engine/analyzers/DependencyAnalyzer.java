package dev.pluginguard.engine.analyzers;

import dev.pluginguard.engine.AnalysisContext;
import dev.pluginguard.engine.Analyzer;
import dev.pluginguard.engine.model.Dependency;
import dev.pluginguard.engine.model.ResourceFile;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.Properties;

/**
 * Builds a best-effort SBOM (list of bundled dependencies) from Maven {@code pom.properties}
 * descriptors that build tools embed in shaded JARs, plus any nested JAR names. Known-CVE lookup
 * is intentionally out of scope for this version — this only inventories what is bundled.
 */
@Component
@Order(35)
public class DependencyAnalyzer implements Analyzer {

    @Override
    public String name() {
        return "dependencies";
    }

    @Override
    public void analyze(AnalysisContext ctx) {
        for (ResourceFile res : ctx.jar().resources()) {
            String name = res.name().toLowerCase(Locale.ROOT);
            if (name.startsWith("meta-inf/maven/") && name.endsWith("pom.properties")) {
                parsePomProperties(ctx, res);
            }
        }
        for (String nested : ctx.jar().nestedJars()) {
            String simple = nested.substring(nested.lastIndexOf('/') + 1);
            ctx.addDependency(new Dependency(simple, null, "nested-jar"));
        }
    }

    private void parsePomProperties(AnalysisContext ctx, ResourceFile res) {
        try {
            Properties props = new Properties();
            props.load(new java.io.ByteArrayInputStream(res.bytes()));
            String groupId = props.getProperty("groupId");
            String artifactId = props.getProperty("artifactId");
            String version = props.getProperty("version");
            if (artifactId != null) {
                String depName = groupId != null ? groupId + ":" + artifactId : artifactId;
                ctx.addDependency(new Dependency(depName, version, "pom.properties"));
            }
        } catch (Exception ignored) {
            // best-effort: skip malformed descriptors
        }
    }
}
