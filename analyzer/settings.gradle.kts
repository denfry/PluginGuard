rootProject.name = "pluginguard-analyzer"

// Phase 3 in-container sandbox runtime (JVM agent + mock Bukkit harness). Built as a separate
// plain-Java jar so the dangerous org.bukkit stubs and the agent's Premain-Class never leak onto
// the analyzer service's classpath. It is only ever copied into the isolated sandbox image.
include("sandbox-runtime")
