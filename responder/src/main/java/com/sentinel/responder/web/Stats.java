package com.sentinel.responder.web;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import org.springframework.stereotype.Component;

/** Counters exposed on /_gw/stats (analyst or admin JWT). */
@Component
public class Stats {
    final AtomicLong requests = new AtomicLong();
    final AtomicLong blocked = new AtomicLong();
    final AtomicLong rateLimited = new AtomicLong();
    final AtomicLong unauthorized = new AtomicLong();
    final AtomicLong forbidden = new AtomicLong();
    final AtomicLong proxied = new AtomicLong();
    final AtomicLong upstreamErrors = new AtomicLong();
    final AtomicLong storeErrors = new AtomicLong();

    public Map<String, Long> snapshot() {
        Map<String, Long> m = new LinkedHashMap<>();
        m.put("requests", requests.get());
        m.put("blocked", blocked.get());
        m.put("rateLimited", rateLimited.get());
        m.put("unauthorized", unauthorized.get());
        m.put("forbidden", forbidden.get());
        m.put("proxied", proxied.get());
        m.put("upstreamErrors", upstreamErrors.get());
        m.put("storeErrors", storeErrors.get());
        return m;
    }
}
