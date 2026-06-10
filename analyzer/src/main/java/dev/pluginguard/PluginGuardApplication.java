package dev.pluginguard;

import dev.pluginguard.config.AnalyzerProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

/**
 * Entry point for the PluginGuard analyzer service.
 *
 * <p>The service performs <strong>static</strong> security analysis of uploaded Minecraft
 * plugin JARs. Uploaded archives are never executed and their classes are never loaded into
 * this JVM — bytecode is parsed read-only with ASM, YAML is parsed in safe mode, and strings
 * are extracted from the constant pool. See {@code engine} package for the analysis pipeline.
 */
// DataSource auto-configuration is excluded so the service runs with NO database by default
// (in-memory report store). When pluginguard.persistence=jdbc, PersistenceConfig builds the
// DataSource explicitly. See dev.pluginguard.api.PersistenceConfig.
@SpringBootApplication(exclude = DataSourceAutoConfiguration.class)
@EnableConfigurationProperties(AnalyzerProperties.class)
public class PluginGuardApplication {

    public static void main(String[] args) {
        SpringApplication.run(PluginGuardApplication.class, args);
    }
}
