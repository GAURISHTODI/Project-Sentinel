package com.sentinel.responder;

import com.sentinel.responder.store.GatewayStore;
import com.sun.net.httpserver.HttpServer;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

/** Test doubles: an in-memory decision store, a recording fake upstream, and JWT/HTTP helpers. */
public final class TestSupport {
    public static final String SECRET = "integration-test-secret-at-least-32-chars";

    private TestSupport() {}

    /** In-memory stand-in for Redis. */
    public static class MemoryStore implements GatewayStore {
        public final Map<String, Boolean> blocked = new ConcurrentHashMap<>();
        public final Map<String, Integer> dynamicLimit = new ConcurrentHashMap<>();
        public final Map<String, Long> counters = new ConcurrentHashMap<>();
        public volatile boolean failing;

        public void reset() {
            blocked.clear();
            dynamicLimit.clear();
            counters.clear();
            failing = false;
        }

        @Override
        public Decision check(String ip, int defaultLimit, long minuteEpoch) {
            if (failing) {
                throw new IllegalStateException("store down");
            }
            long n = counters.merge(ip + ":" + minuteEpoch, 1L, Long::sum);
            int limit = Math.min(defaultLimit, dynamicLimit.getOrDefault(ip, defaultLimit));
            return new Decision(blocked.containsKey(ip), limit, n);
        }
    }

    @TestConfiguration
    public static class StoreConfig {
        @Bean
        public MemoryStore memoryStore() {
            return new MemoryStore();
        }
    }

    /** What the fake upstream received most recently. */
    public record Seen(String method, String path, String query, Map<String, List<String>> headers, String body) {}

    /** Tiny HTTP server that records requests and returns canned responses. */
    public static class FakeUpstream {
        public final HttpServer server;
        public final CopyOnWriteArrayList<Seen> requests = new CopyOnWriteArrayList<>();

        public FakeUpstream() throws IOException {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", ex -> {
                byte[] in = ex.getRequestBody().readAllBytes();
                Map<String, List<String>> h = new java.util.TreeMap<>(String.CASE_INSENSITIVE_ORDER);
                ex.getRequestHeaders().forEach(h::put);
                requests.add(new Seen(ex.getRequestMethod(), ex.getRequestURI().getRawPath(), ex.getRequestURI().getRawQuery(),
                        h, new String(in, StandardCharsets.UTF_8)));
                String path = ex.getRequestURI().getPath();
                try {
                    if (path.equals("/slow")) {
                        Thread.sleep(3000);
                    }
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                }
                int status = 200;
                byte[] out = "{\"upstream\":\"ok\"}".getBytes(StandardCharsets.UTF_8);
                if (path.equals("/boom")) {
                    status = 500;
                    out = "upstream exploded".getBytes(StandardCharsets.UTF_8);
                } else if (path.equals("/redirect")) {
                    status = 302;
                    ex.getResponseHeaders().add("Location", "http://127.0.0.1:1/elsewhere");
                }
                ex.getResponseHeaders().add("X-Upstream", "yes");
                ex.getResponseHeaders().add("Content-Type", "application/json");
                ex.sendResponseHeaders(status, out.length == 0 ? -1 : out.length);
                ex.getResponseBody().write(out);
                ex.close();
            });
            server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool()); // /slow must not block others
            server.start();
        }

        public int port() {
            return server.getAddress().getPort();
        }

        public Seen last() {
            return requests.get(requests.size() - 1);
        }

        public void stop() {
            server.stop(0);
        }
    }

    public static String jwt(String role, long expInSeconds) {
        return Jwts.builder().issuer("sentinel").subject("tester").claim("role", role).id(UUID.randomUUID().toString())
                .issuedAt(new Date()).expiration(new Date(System.currentTimeMillis() + expInSeconds * 1000))
                .signWith(Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8)), Jwts.SIG.HS256).compact();
    }

    private static final HttpClient CLIENT = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();

    /** Sends the request line exactly as given (no client-side path normalisation of the encoded form). */
    public static HttpResponse<String> send(int port, String method, String rawPathAndQuery, String body, String... headers) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + rawPathAndQuery))
                .method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        for (int i = 0; i + 1 < headers.length; i += 2) {
            b.header(headers[i], headers[i + 1]);
        }
        return CLIENT.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    /** Sends a hand-written request line over a raw socket and returns the HTTP status code. */
    public static int rawStatus(int port, String requestLine) throws Exception {
        try (var socket = new java.net.Socket("127.0.0.1", port)) {
            socket.setSoTimeout(5000);
            String request = String.join("\r\n", requestLine, "Host: 127.0.0.1", "Connection: close", "", "");
            socket.getOutputStream().write(request.getBytes(StandardCharsets.ISO_8859_1));
            String status = new java.io.BufferedReader(new java.io.InputStreamReader(socket.getInputStream(), StandardCharsets.ISO_8859_1)).readLine();
            return Integer.parseInt(status.split(" ")[1]);
        }
    }

    public static HttpResponse<String> get(int port, String path, String... headers) throws Exception {
        return send(port, "GET", path, null, headers);
    }
}
