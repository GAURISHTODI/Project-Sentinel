package com.sentinel.shop;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * Sentinel lab target. v1 is INTENTIONALLY VULNERABLE (SQL injection, XSS, IDOR, weak auth, ...);
 * v2 is the fixed version. The behaviour is selected by {@code shop.version} (v1 | v2).
 * Run only on the isolated lab network.
 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class ShopApplication {
    public static void main(String[] args) {
        SpringApplication.run(ShopApplication.class, args);
    }
}
