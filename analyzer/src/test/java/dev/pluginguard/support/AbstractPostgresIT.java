package dev.pluginguard.support;

import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Base for integration tests that exercise the {@code postgres} profile against a real PostgreSQL
 * started by Testcontainers (requires a Docker daemon). Flyway runs the migrations on startup.
 *
 * <p>{@code @DynamicPropertySource} overrides the {@code ${PLUGINGUARD_DB_URL}} placeholder from
 * {@code application-postgres.yml} with the container's connection details.
 */
@SpringBootTest
@ActiveProfiles("postgres")
@Testcontainers
public abstract class AbstractPostgresIT {

    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @DynamicPropertySource
    static void datasourceProps(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
    }
}
