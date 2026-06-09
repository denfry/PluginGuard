plugins {
    java
}

group = "dev.pluginguard"
version = "0.1.0"
description = "PluginGuard sandbox runtime — JVM agent + mock Bukkit harness that runs inside the isolated container"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

repositories {
    mavenCentral()
}

dependencies {
    // ASM only — used by the JVM agent to instrument the plugin's dangerous call sites. No Spring,
    // no Bukkit: the org.bukkit.* classes here are hand-written stubs compiled from src/main.
    implementation("org.ow2.asm:asm:9.7.1")

    testImplementation(platform("org.junit:junit-bom:5.11.4"))
    testImplementation("org.junit.jupiter:junit-jupiter")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.withType<JavaCompile> {
    options.encoding = "UTF-8"
    options.compilerArgs.add("-parameters")
}

tasks.withType<Test> {
    useJUnitPlatform()
}

tasks.jar {
    // The jar is its own java-agent (Premain/Agent-Class) and the harness entrypoint (Main-Class),
    // so the container can run: java -javaagent:runtime.jar -jar runtime.jar <plugin.jar> <log>
    manifest {
        attributes(
            "Premain-Class" to "dev.pluginguard.sandbox.runtime.SandboxAgent",
            "Agent-Class" to "dev.pluginguard.sandbox.runtime.SandboxAgent",
            "Can-Retransform-Classes" to "true",
            "Main-Class" to "dev.pluginguard.sandbox.runtime.MockBukkitHarness",
            "Implementation-Title" to "pluginguard-sandbox-runtime",
            "Implementation-Version" to project.version
        )
    }
    // Fold the ASM classes into this jar so a single -javaagent file is fully self-contained.
    from(configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) })
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
}
