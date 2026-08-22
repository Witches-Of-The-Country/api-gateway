# ==========================================
# ESTÁGIO 1: Build
# ==========================================
FROM maven:3.9.6-eclipse-temurin-21 AS builder

WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline
COPY src ./src
RUN mvn clean package -DskipTests

# ==========================================
# ESTÁGIO 2: Run
# ==========================================
FROM eclipse-temurin:21-jre-alpine

# Create a non-root user and group
RUN addgroup -S spring && adduser -S spring -G spring
USER spring:spring

WORKDIR /app
COPY --from=builder /app/target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
