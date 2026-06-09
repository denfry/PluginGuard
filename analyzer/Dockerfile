# --- Build stage: compile and package the Spring Boot fat jar ---
FROM eclipse-temurin:21-jdk AS build
WORKDIR /app

# Cache the Gradle distribution + dependencies across builds.
COPY gradlew settings.gradle.kts build.gradle.kts gradle.properties ./
COPY gradle ./gradle
RUN ./gradlew --no-daemon dependencies > /dev/null 2>&1 || true

COPY src ./src
RUN ./gradlew --no-daemon clean bootJar

# --- Run stage: minimal JRE image ---
FROM eclipse-temurin:21-jre AS run
WORKDIR /app

# Run as a non-root user.
RUN useradd -r -u 1001 pluginguard
USER pluginguard

COPY --from=build /app/build/libs/*.jar app.jar

EXPOSE 8080
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75", "-jar", "app.jar"]
