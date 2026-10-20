# ==============================================================================
# Stage 1: Build & Package (Java 21 + Maven)
# ==============================================================================
FROM eclipse-temurin:21-jdk AS builder

WORKDIR /build

# Copy Maven Wrapper and configuration files
COPY .mvn/ .mvn/
COPY mvnw pom.xml ./

# Convert line endings if built from Windows and cache offline dependencies
RUN sed -i 's/\r$//' mvnw && chmod +x mvnw && ./mvnw dependency:go-offline -B

# Copy application source code
COPY src/ src/

# Build Spring Boot executable JAR skipping tests
RUN ./mvnw clean package -DskipTests -B

# ==============================================================================
# Stage 2: Minimal Secure Runtime (Java 21 JRE)
# ==============================================================================
FROM eclipse-temurin:21-jre

# Metadata & Security labeling
LABEL maintainer="MemoryGuard DevSecOps" \
      description="MemoryGuard Backend AI Memory Security Platform" \
      version="0.0.1-SNAPSHOT"

WORKDIR /app

# Create unprivileged system group and user
RUN groupadd -r memoryguard && useradd -r -g memoryguard -d /app -s /sbin/nologin memoryguard

# Copy compiled JAR from builder stage
COPY --from=builder /build/target/memoryguard-backend-0.0.1-SNAPSHOT.jar app.jar

# Enforce secure ownership and permissions
RUN chown -R memoryguard:memoryguard /app && chmod 400 app.jar

# Switch to unprivileged user
USER memoryguard

# Dynamic Port handling: Render sets $PORT dynamically; default to 8081 for local development
ENV PORT=8081 \
    JAVA_TOOL_OPTIONS="-XX:+UseG1GC -XX:MaxRAMPercentage=75.0 -XX:+ExitOnOutOfMemoryError"

# Documentation of dynamic port binding
EXPOSE 8081

# Proper signal handling & dynamic port binding
ENTRYPOINT ["sh", "-c", "exec java -Dserver.port=${PORT} -jar app.jar"]
