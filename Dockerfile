# CyberVault Security Platform - Multi-stage Docker Build
# Optimized for production with security best practices

# Stage 1: Build React Frontend
FROM node:18-alpine AS frontend-builder

# Set working directory
WORKDIR /build

# Create non-root user
RUN addgroup -g 1001 -S nodegroup && \
    adduser -u 1001 -S nodeuser -G nodegroup

# Copy package files
COPY frontend/package*.json ./

# Install dependencies with lock file for reproducible builds
RUN npm ci --omit=dev --no-audit --no-fund || npm install --omit=dev --no-audit --no-fund

# Copy source code
COPY frontend/ ./

# Build production application
RUN npm run build:prod

# Stage 2: Build Java Backend
FROM maven:3.9.5-eclipse-temurin-17-alpine AS backend-builder

# Set working directory
WORKDIR /build

# Create non-root user for build process
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Copy Maven configuration
COPY backend/java/pom.xml .
COPY backend/java/src ./src

# Download dependencies (cached layer)
RUN mvn dependency:go-offline -B

# Copy React build into Spring Boot resources
COPY --from=frontend-builder /build/build ./src/main/resources/static

# Build application
RUN mvn clean package -DskipTests -B && \
    mv target/*.jar app.jar

# Stage 3: Build C/C++ Components
FROM alpine:3.18 AS native-builder

# Install build dependencies
RUN apk add --no-cache \
    gcc \
    g++ \
    musl-dev \
    openssl-dev \
    libpcap-dev \
    make

WORKDIR /build

# Copy source files
COPY backend/c/encrypt.c ./
COPY backend/cpp/sniffer.cpp ./

# Compile with security flags
RUN gcc -o encrypt encrypt.c \
    -lssl -lcrypto \
    -O2 -D_FORTIFY_SOURCE=2 \
    -fstack-protector-strong \
    -Wl,-z,relro,-z,now && \
    g++ -o sniffer sniffer.cpp \
    -lpcap \
    -O2 -D_FORTIFY_SOURCE=2 \
    -fstack-protector-strong \
    -Wl,-z,relro,-z,now

# Stage 4: Production Runtime
FROM eclipse-temurin:17-jre-alpine

# Metadata
LABEL maintainer="Arap Bett <arap.bett@cybervault.com>" \
      version="2.0.0" \
      description="CyberVault Security Operations Platform" \
      org.opencontainers.image.title="CyberVault" \
      org.opencontainers.image.description="Advanced Cybersecurity Operations Terminal" \
      org.opencontainers.image.version="2.0.0" \
      org.opencontainers.image.authors="Arap Bett" \
      org.opencontainers.image.vendor="CyberVault Security" \
      org.opencontainers.image.licenses="MIT"

# Install runtime dependencies only
RUN apk add --no-cache \
    libssl3 \
    libcrypto3 \
    libpcap \
    dumb-init \
    curl \
    && rm -rf /var/cache/apk/*

# Create application directory
WORKDIR /app

# Create non-root user and group
RUN addgroup -g 1001 -S cybervault && \
    adduser -u 1001 -S cybervault -G cybervault -h /app

# Create required directories with proper permissions
RUN mkdir -p /app/backend/c /app/backend/cpp /app/static /app/logs /app/temp && \
    chown -R cybervault:cybervault /app

# Copy compiled binaries and JAR from builder stages
COPY --from=native-builder --chown=cybervault:cybervault /build/encrypt /app/backend/c/
COPY --from=native-builder --chown=cybervault:cybervault /build/sniffer /app/backend/cpp/
COPY --from=backend-builder --chown=cybervault:cybervault /build/app.jar /app/

# Set executable permissions
RUN chmod +x /app/backend/c/encrypt /app/backend/cpp/sniffer

# Switch to non-root user
USER cybervault:cybervault

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8080/actuator/health || exit 1

# Expose port
EXPOSE 8080

# Set environment variables
ENV SPRING_PROFILES_ACTIVE=production \
    JAVA_OPTS="-Xms512m -Xmx1g -Djava.security.egd=file:/dev/./urandom" \
    SERVER_PORT=8080

# Use dumb-init for proper signal handling
ENTRYPOINT ["dumb-init", "--"]

# Start application with optimized JVM settings
CMD ["sh", "-c", "java $JAVA_OPTS -jar app.jar"]

# Security: Run as non-root, minimal base image, security updates applied
