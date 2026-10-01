package com.sentinel.shop;

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/** Settings under the {@code shop.*} prefix. */
@ConfigurationProperties(prefix = "shop")
public record ShopProperties(
        /** v1 = intentionally vulnerable, v2 = fixed. */
        @DefaultValue("v1") String version,
        /** Directory served by /api/files. */
        @DefaultValue("./data/files") String filesDir,
        /** Initial admin password for v2 (v1 always uses the weak default). Empty = random. */
        @DefaultValue("") String adminPassword,
        /** Proxies whose X-Forwarded-For header is trusted (the Sentinel gateway). */
        @DefaultValue({}) List<String> trustedProxies,
        @DefaultValue Kafka kafka) {

    public record Kafka(
            @DefaultValue("false") boolean enabled,
            @DefaultValue("kafka:9092") String bootstrap,
            @DefaultValue("logs.app") String accessTopic,
            @DefaultValue("logs.auth") String authTopic) {}

    public boolean secure() {
        return "v2".equalsIgnoreCase(version);
    }
}
