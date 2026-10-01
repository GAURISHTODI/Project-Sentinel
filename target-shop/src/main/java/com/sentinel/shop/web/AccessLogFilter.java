package com.sentinel.shop.web;

import com.sentinel.shop.ShopProperties;
import com.sentinel.shop.events.EventSink;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingResponseWrapper;

/** Emits one structured access event per request (raw URI incl. query, which may be hostile input). */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class AccessLogFilter extends OncePerRequestFilter {
    private final EventSink events;
    private final ShopProperties props;

    public AccessLogFilter(EventSink events, ShopProperties props) {
        this.events = events;
        this.props = props;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        long start = System.nanoTime();
        ContentCachingResponseWrapper wrapped = new ContentCachingResponseWrapper(res);
        try {
            chain.doFilter(req, wrapped);
        } finally {
            String uri = req.getRequestURI() + (req.getQueryString() == null ? "" : "?" + req.getQueryString());
            events.access(new EventSink.AccessEvent(
                    System.currentTimeMillis() / 1000.0,
                    ClientIp.resolve(req, props),
                    req.getMethod(),
                    uri.length() > 2048 ? uri.substring(0, 2048) : uri,
                    wrapped.getStatus(),
                    req.getHeader("User-Agent"),
                    null,
                    wrapped.getContentSize(),
                    (System.nanoTime() - start) / 1_000_000));
            wrapped.copyBodyToResponse();
        }
    }
}
