plugins {
    java
    id("org.springframework.boot") version "3.5.9"
    id("io.spring.dependency-management") version "1.1.7"
}

group = "dev.pluginguard"
version = "0.1.0"
description = "PluginGuard analyzer — static security analysis for Minecraft plugin JARs"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-web")

    // ASM — bytecode parsing for the core analyzer (parse-only, never loads/links classes)
    implementation("org.ow2.asm:asm:9.7.1")
    implementation("org.ow2.asm:asm-tree:9.7.1")
    // ASM dataflow framework — used to fold String constants (locals, StringBuilder, concat) so
    // reflective targets assembled from more than one ldc are still resolved.
    implementation("org.ow2.asm:asm-analysis:9.7.1")

    // SnakeYAML for plugin.yml parsing (version managed by Spring Boot BOM)
    implementation("org.yaml:snakeyaml")

    // Persistence — active only under the `postgres` profile (see application-postgres.yml).
    // The default profile excludes the JDBC/Flyway auto-configuration so no database is required.
    implementation("org.springframework.boot:spring-boot-starter-jdbc")
    runtimeOnly("org.postgresql:postgresql")
    implementation("org.flywaydb:flyway-core")
    implementation("org.flywaydb:flyway-database-postgresql")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<Test> {
    useJUnitPlatform()
}

tasks.withType<JavaCompile> {
    options.encoding = "UTF-8"
    options.compilerArgs.add("-parameters")
}
