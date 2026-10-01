package com.sentinel.shop.web;

import com.sentinel.shop.ShopProperties;
import jakarta.servlet.http.HttpServletRequest;

/** Resolves the real client address. X-Forwarded-For is honoured only from a trusted proxy. */
public final class ClientIp {
    private ClientIp() {}

    public static String resolve(HttpServletRequest req, ShopProperties props) {
        String remote = req.getRemoteAddr();
        String xff = req.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank() && props.trustedProxies().contains(remote)) {
            String first = xff.split(",")[0].trim();
            if (first.length() <= 64 && first.matches("[0-9a-fA-F:.]+")) {
                return first;
            }
        }
        return remote;
    }
}
