package com.sentinel.responder.web;

import com.sentinel.responder.GatewayProperties;
import com.sentinel.responder.security.JwtVerifier;
import com.sentinel.responder.security.PathNormalizer;
import com.sentinel.responder.store.GatewayStore;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Applies Sentinel's decisions to every request, in this order:
 * 1. canonicalise the path (malformed -> 400)   2. blocklist (-> 403)   3. rate limit (-> 429)
 * 4. authentication / role for admin routes (-> 401 / 403).
 * The canonical path that was authorised is stored on the request and is the one that gets forwarded.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class GatewayFilter extends OncePerRequestFilter {
    private static final Logger log = LoggerFactory.getLogger(GatewayFilter.class);
    public static final String CANONICAL_PATH = "gateway.canonicalPath";
    static final String GW_PREFIX = "/_gw";

    private final GatewayProperties props;
    private final GatewayStore store;
    private final JwtVerifier jwt;
    private final Stats stats;

    public GatewayFilter(GatewayProperties props, GatewayStore store, JwtVerifier jwt, Stats stats) {
        this.props = props;
        this.store = store;
        this.jwt = jwt;
        this.stats = stats;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        stats.requests.incrementAndGet();
        Optional<String> canonical = PathNormalizer.normalize(req.getRequestURI());
        if (canonical.isEmpty()) {
            reply(res, 400, "bad request", null);
            return;
        }
        String path = canonical.get();
        req.setAttribute(CANONICAL_PATH, path);
        if (PathNormalizer.under(path, GW_PREFIX + "/health")) {
            chain.doFilter(req, res);
            return;
        }

        String ip = req.getRemoteAddr();
        long now = System.currentTimeMillis() / 1000;
        GatewayStore.Decision decision;
        try {
            decision = store.check(ip, props.rateLimitPerMinute(), now / 60);
        } catch (RuntimeException e) {
            stats.storeErrors.incrementAndGet();
            log.warn("decision store unavailable ({}), failOpen={}", e.getClass().getSimpleName(), props.failOpen());
            if (!props.failOpen()) {
                reply(res, 503, "temporarily unavailable", null);
                return;
            }
            decision = new GatewayStore.Decision(false, props.rateLimitPerMinute(), 0);
        }
        if (decision.blocked()) {
            stats.blocked.incrementAndGet();
            logDecision("blocked", ip, path);
            reply(res, 403, "blocked", null);
            return;
        }
        if (decision.count() > decision.limit()) {
            stats.rateLimited.incrementAndGet();
            logDecision("rate_limited", ip, path);
            reply(res, 429, "too many requests", String.valueOf(60 - (now % 60)));
            return;
        }

        if (PathNormalizer.under(path, GW_PREFIX)) {
            // gateway admin API: analyst may read, only admin may change anything
            boolean read = "GET".equals(req.getMethod());
            if (!authorize(req, res, bearer(req.getHeader("Authorization")), read ? "analyst" : "admin", ip, path)) {
                return;
            }
        } else if (PathNormalizer.underAny(path, props.adminPrefixes())) {
            if (!authorize(req, res, req.getHeader("X-Sentinel-Token"), "admin", ip, path)) {
                return;
            }
        }
        chain.doFilter(req, res);
    }

    private boolean authorize(HttpServletRequest req, HttpServletResponse res, String token, String needed, String ip, String path)
            throws IOException {
        Optional<JwtVerifier.Principal> who = jwt.verify(token);
        if (who.isEmpty()) {
            stats.unauthorized.incrementAndGet();
            logDecision("unauthorized", ip, path);
            res.setHeader("WWW-Authenticate", "Bearer");
            reply(res, 401, "authentication required", null);
            return false;
        }
        if ("admin".equals(needed) && !who.get().isAdmin()) {
            stats.forbidden.incrementAndGet();
            logDecision("forbidden", ip, path);
            reply(res, 403, "forbidden", null);
            return false;
        }
        return true;
    }

    private static String bearer(String header) {
        return header != null && header.startsWith("Bearer ") ? header.substring(7) : null;
    }

    private static void reply(HttpServletResponse res, int status, String message, String retryAfter) throws IOException {
        res.setStatus(status);
        res.setContentType("application/json");
        res.setHeader("Cache-Control", "no-store");
        res.setHeader("X-Content-Type-Options", "nosniff");
        if (retryAfter != null) {
            res.setHeader("Retry-After", retryAfter);
        }
        res.getOutputStream().write(("{\"error\":\"" + message + "\"}").getBytes(StandardCharsets.UTF_8));
    }

    /** Request data is attacker-controlled: never write it to a log line unsanitised. */
    static String clean(String s) {
        String t = s.length() > 200 ? s.substring(0, 200) : s;
        return t.replaceAll("[\\p{Cntrl}]", "?");
    }

    private void logDecision(String decision, String ip, String path) {
        log.info("decision={} ip={} path={}", decision, clean(ip), clean(path));
    }
}
