# STAGE 1: Build the app
# Maven image from DockerHub
FROM maven:3.9-eclipse-temurin-17-noble AS build

# Set the working directory
WORKDIR /app

# Copy pom.xml first to cache dependecies
COPY pom.xml .
RUN mvn dependency:go-offline

COPY src ./src

# Build the .jar file (and skip tests, which should run in CI)
RUN mvn clean package -DskipTests

# STAGE 2: Create the final image
# Use a minimal Java Runtime Environment image for Java 17
FROM eclipse-temurin:17-jre-focal

WORKDIR /app

# Copy only the built .jar file from 'build' stage
COPY --from=build /app/target/*.jar app.jar

# Expose the port Spring Boot app run on
EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]