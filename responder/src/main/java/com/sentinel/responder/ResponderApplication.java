package com.sentinel.responder;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * Sentinel responder gateway. Sits in front of the application and enforces what the detection engine
 * decides: blocked addresses get 403, rate-limited addresses get 429, admin routes need a valid JWT.
 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class ResponderApplication {
    public static void main(String[] args) {
        SpringApplication.run(ResponderApplication.class, args);
    }
}
