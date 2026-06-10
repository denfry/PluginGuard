package dev.pluginguard.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;

/**
 * Wires the PostgreSQL-backed {@link JdbcReportStore} when {@code pluginguard.persistence=jdbc}.
 *
 * <p>The {@link DataSource} is built explicitly here (Spring's {@code DataSourceAutoConfiguration} is
 * excluded in {@link dev.pluginguard.PluginGuardApplication}) so that, by default, the service starts
 * with no database at all and falls back to the in-memory {@link ScanStore}.
 */
@Configuration
@ConditionalOnProperty(prefix = "pluginguard", name = "persistence", havingValue = "jdbc")
public class PersistenceConfig {

    @Bean
    public DataSource dataSource(Environment env) {
        String url = env.getProperty("spring.datasource.url");
        if (url == null || url.isBlank()) {
            throw new IllegalStateException(
                    "pluginguard.persistence=jdbc requires spring.datasource.url (env "
                            + "SPRING_DATASOURCE_URL), e.g. jdbc:postgresql://host/db?sslmode=require");
        }
        HikariConfig cfg = new HikariConfig();
        cfg.setJdbcUrl(url);
        cfg.setUsername(env.getProperty("spring.datasource.username"));
        cfg.setPassword(env.getProperty("spring.datasource.password"));
        // Small pool: free Postgres tiers cap connections and the service runs on a fractional CPU.
        cfg.setMaximumPoolSize(
                env.getProperty("spring.datasource.hikari.maximum-pool-size", Integer.class, 3));
        cfg.setPoolName("pluginguard-pool");
        return new HikariDataSource(cfg);
    }

    @Bean
    public JdbcTemplate jdbcTemplate(DataSource dataSource) {
        return new JdbcTemplate(dataSource);
    }

    @Bean
    public ReportStore reportStore(JdbcTemplate jdbcTemplate, ObjectMapper objectMapper) {
        return new JdbcReportStore(jdbcTemplate, objectMapper);
    }
}
