# --- Build stage: compile and package the Spring Boot fat jar ---
FROM eclipse-temurin:21-jdk AS build
WORKDIR /app

# Cache the Gradle distribution + dependencies across builds.
COPY gradlew settings.gradle.kts build.gradle.kts gradle.properties ./
COPY gradle ./gradle
COPY sandbox-runtime/build.gradle.kts ./sandbox-runtime/build.gradle.kts
RUN ./gradlew --no-daemon dependencies > /dev/null 2>&1 || true

COPY src ./src
COPY sandbox-runtime/src ./sandbox-runtime/src
# Build the Spring Boot app and the (Phase 3) sandbox-runtime agent jar.
RUN ./gradlew --no-daemon clean bootJar :sandbox-runtime:jar

# --- Run stage: minimal JRE image ---
FROM eclipse-temurin:21-jre AS run
WORKDIR /app

# Run as a non-root user.
RUN useradd -r -u 1001 pluginguard
USER pluginguard

COPY --from=build /app/build/libs/*.jar app.jar
# The sandbox-runtime agent jar (used only if pluginguard.sandbox.enabled=true and Docker is wired in).
COPY --from=build /app/sandbox-runtime/build/libs/sandbox-runtime-*.jar /opt/pluginguard/sandbox-runtime.jar

EXPOSE 8080
# Tuned for small/shared free instances (≈512 MB, fractional CPU): cap the heap well under the
# container limit (metaspace + thread stacks + direct buffers live outside it) and use the
# low-footprint serial collector. Override MaxRAMPercentage upward on a larger plan.
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=60", "-XX:+UseSerialGC", "-jar", "app.jar"]
