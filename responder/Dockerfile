# Responder gateway image. Build the jar first: (cd responder && mvn -q package)
FROM eclipse-temurin:21-jre
RUN useradd --system --uid 10002 --home-dir /app gateway
WORKDIR /app
COPY target/responder-1.0.0.jar app.jar
USER 10002
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
