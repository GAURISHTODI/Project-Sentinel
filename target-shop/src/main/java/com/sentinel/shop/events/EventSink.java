package com.sentinel.shop.events;

/** Where structured access/auth events go. Implementations must never block or fail a request. */
public interface EventSink {

    /** One HTTP request, logged after the response is produced. */
    record AccessEvent(
            double ts, String clientIp, String method, String uri, int status,
            String userAgent, String user, long bytes, long durationMs) {}

    /** One authentication attempt. {@code username} is attacker-controlled input. */
    record AuthEvent(double ts, String clientIp, String username, String outcome, String userAgent) {}

    void access(AccessEvent event);

    void auth(AuthEvent event);
}
