package com.sentinel.shop.web;

import com.sentinel.shop.ShopProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * v1 VULNERABLE (F-13): wildcard CORS with credentials, a version banner, and none of the standard
 * browser security headers. v2 FIXED: security headers on every response, no CORS, no banner.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 1)
public class HeadersFilter extends OncePerRequestFilter {
    private final ShopProperties props;

    public HeadersFilter(ShopProperties props) {
        this.props = props;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        if (props.secure()) {
            res.setHeader("X-Content-Type-Options", "nosniff");
            res.setHeader("X-Frame-Options", "DENY");
            res.setHeader("Referrer-Policy", "no-referrer");
            res.setHeader("Cache-Control", "no-store");
            // base-uri and form-action do not fall back to default-src per the CSP spec, so they are
            // listed explicitly (ZAP rule 10055: "Failure to Define Directive with No Fallback").
            res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self'; object-src 'none'; "
                    + "frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
            res.setHeader("Permissions-Policy", "geolocation=(), camera=(), microphone=()");
        } else {
            res.setHeader("Access-Control-Allow-Origin", "*");
            res.setHeader("Access-Control-Allow-Credentials", "true");
            res.setHeader("X-Powered-By", "target-shop v1 (Spring Boot 3.3.5; Java 21; H2)");
        }
        chain.doFilter(req, res);
    }
}
