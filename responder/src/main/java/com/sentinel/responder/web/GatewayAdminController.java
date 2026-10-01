package com.sentinel.responder.web;

import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** Gateway-owned endpoints. /_gw/stats is protected by the filter (JWT with analyst or admin role). */
@RestController
public class GatewayAdminController {
    private final Stats stats;

    public GatewayAdminController(Stats stats) {
        this.stats = stats;
    }

    @GetMapping("/_gw/health")
    public Map<String, String> health() {
        return Map.of("status", "ok");
    }

    @GetMapping("/_gw/stats")
    public Map<String, Long> stats() {
        return stats.snapshot();
    }
}
