# Lab image for the Sentinel target shop. Build the jar first: (cd target-shop && mvn -q package)
# INTENTIONALLY VULNERABLE when SHOP_VERSION=v1. Run only on the internal `lab` network.
FROM eclipse-temurin:21-jre
RUN useradd --system --uid 10001 --home-dir /app shop
WORKDIR /app
COPY target/target-shop-1.0.0.jar app.jar
COPY data /app/data
USER 10001
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
