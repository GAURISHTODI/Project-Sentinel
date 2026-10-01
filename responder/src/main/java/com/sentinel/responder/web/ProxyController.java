package com.sentinel.responder.web;

import com.sentinel.responder.GatewayProperties;
import com.sentinel.responder.security.PathNormalizer;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Reverse proxy to the protected application. It forwards the canonical path that was authorised,
 * sets X-Forwarded-For from the socket address (client-supplied values are discarded), strips hop-by-hop
 * and gateway-credential headers, bounds request and response sizes and never follows redirects.
 */
@RestController
public class ProxyController {
    private static final Logger log = LoggerFactory.getLogger(ProxyController.class);
    private static final Set<String> METHODS = Set.of("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS");
    private static final Set<String> DROP_REQUEST = Set.of(
            "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer",
            "transfer-encoding", "upgrade", "host", "content-length", "expect",
            "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host", "x-real-ip", "forwarded",
            "x-sentinel-token");
    private static final Set<String> DROP_RESPONSE = Set.of(
            "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer",
            "transfer-encoding", "upgrade", "content-length");

    private final GatewayProperties props;
    private final Stats stats;
    private final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(2))
            .followRedirects(HttpClient.Redirect.NEVER)
            .version(HttpClient.Version.HTTP_1_1)
            .build();

    public ProxyController(GatewayProperties props, Stats stats) {
        this.props = props;
        this.stats = stats;
    }

    @RequestMapping("/**")
    public void proxy(HttpServletRequest req, HttpServletResponse res) throws IOException {
        if (!METHODS.contains(req.getMethod())) {
            error(res, 405, "method not allowed");
            return;
        }
        String canonical = (String) req.getAttribute(GatewayFilter.CANONICAL_PATH);
        if (canonical == null) {
            error(res, 400, "bad request");
            return;
        }
        byte[] body = req.getInputStream().readNBytes((int) props.maxRequestBytes() + 1);
        if (body.length > props.maxRequestBytes()) {
            error(res, 413, "request too large");
            return;
        }
        String query = req.getQueryString();
        URI target;
        try {
            target = URI.create(props.upstream() + PathNormalizer.encode(canonical) + (query == null ? "" : "?" + encodeQuery(query)));
        } catch (IllegalArgumentException e) {
            error(res, 400, "bad request");
            return;
        }
        HttpRequest.Builder b = HttpRequest.newBuilder(target)
                .timeout(Duration.ofMillis(props.upstreamTimeoutMs()))
                .method(req.getMethod(), body.length == 0 ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofByteArray(body));
        Enumeration<String> names = req.getHeaderNames();
        while (names.hasMoreElements()) {
            String name = names.nextElement();
            if (DROP_REQUEST.contains(name.toLowerCase(Locale.ROOT))) {
                continue;
            }
            Enumeration<String> values = req.getHeaders(name);
            while (values.hasMoreElements()) {
                b.header(name, values.nextElement());
            }
        }
        b.header("X-Forwarded-For", req.getRemoteAddr()); // the socket address, never a client-supplied value
        b.header("X-Forwarded-Proto", "http");

        try {
            HttpResponse<byte[]> up = client.send(b.build(), HttpResponse.BodyHandlers.ofByteArray());
            if (up.body().length > props.maxResponseBytes()) {
                stats.upstreamErrors.incrementAndGet();
                error(res, 502, "bad gateway");
                return;
            }
            res.setStatus(up.statusCode());
            up.headers().map().forEach((name, values) -> {
                if (!DROP_RESPONSE.contains(name.toLowerCase(Locale.ROOT))) {
                    values.forEach(v -> res.addHeader(name, v));
                }
            });
            res.getOutputStream().write(up.body());
            stats.proxied.incrementAndGet();
        } catch (HttpTimeoutException e) {
            stats.upstreamErrors.incrementAndGet();
            error(res, 504, "gateway timeout");
        } catch (IOException e) {
            stats.upstreamErrors.incrementAndGet();
            log.warn("upstream error: {}", e.getClass().getSimpleName());
            error(res, 502, "bad gateway");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            error(res, 503, "unavailable");
        }
    }

    /** Percent-encodes characters that are illegal in a URI query but leaves existing %XX sequences alone. */
    static String encodeQuery(String q) {
        StringBuilder sb = new StringBuilder();
        byte[] bytes = q.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        for (int i = 0; i < bytes.length; i++) {
            int c = bytes[i] & 0xff;
            boolean ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                    || "-._~!$&'()*+,;=:@/?%".indexOf(c) >= 0;
            if (ok) {
                sb.append((char) c);
            } else {
                sb.append('%').append(String.format("%02X", c));
            }
        }
        return sb.toString();
    }

    private static void error(HttpServletResponse res, int status, String message) throws IOException {
        res.setStatus(status);
        res.setContentType("application/json");
        res.setHeader("Cache-Control", "no-store");
        res.getOutputStream().write(("{\"error\":\"" + message + "\"}").getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
}
