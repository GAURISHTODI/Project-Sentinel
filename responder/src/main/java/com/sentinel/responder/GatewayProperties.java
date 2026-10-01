package com.sentinel.responder;

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/** Settings under the {@code gateway.*} prefix. */
@ConfigurationProperties(prefix = "gateway")
public record GatewayProperties(
        /** Base URL of the protected application. */
        @DefaultValue("http://172.30.0.11:8080") String upstream,
        /** HS256 secret shared with the Sentinel API (>= 32 characters). The gateway refuses to start without it. */
        @DefaultValue("") String jwtSecret,
        @DefaultValue("sentinel") String issuer,
        /** Requests per minute per client IP unless Sentinel has set a lower dynamic limit. */
        @DefaultValue("300") int rateLimitPerMinute,
        /** If Redis is unreachable: true = keep serving (availability), false = answer 503 (strict). */
        @DefaultValue("true") boolean failOpen,
        @DefaultValue("1048576") long maxRequestBytes,
        @DefaultValue("5242880") long maxResponseBytes,
        @DefaultValue("10000") int upstreamTimeoutMs,
        /** Paths that need an admin JWT in the X-Sentinel-Token header. */
        @DefaultValue("/admin") List<String> adminPrefixes,
        @DefaultValue Redis redis) {

    public record Redis(
            @DefaultValue("redis") String host,
            @DefaultValue("6379") int port,
            @DefaultValue("") String password,
            @DefaultValue("200") int timeoutMs) {}
}
