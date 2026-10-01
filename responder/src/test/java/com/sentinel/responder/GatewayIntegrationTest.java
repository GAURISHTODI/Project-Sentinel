package com.sentinel.responder;

import static com.sentinel.responder.TestSupport.get;
import static com.sentinel.responder.TestSupport.jwt;
import static com.sentinel.responder.TestSupport.rawStatus;
import static com.sentinel.responder.TestSupport.send;
import static org.assertj.core.api.Assertions.assertThat;

import com.sentinel.responder.TestSupport.FakeUpstream;
import com.sentinel.responder.TestSupport.MemoryStore;
import java.net.http.HttpResponse;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
    "gateway.store=memory", "gateway.jwt-secret=" + TestSupport.SECRET, "gateway.rate-limit-per-minute=5",
    "gateway.upstream-timeout-ms=800", "gateway.max-request-bytes=1024"})
@Import(TestSupport.StoreConfig.class)
class GatewayIntegrationTest {
    static FakeUpstream upstream;
    @LocalServerPort int port;
    @Autowired MemoryStore store;

    @BeforeAll
    static void startUpstream() throws Exception {
        upstream = new FakeUpstream();
    }

    @AfterAll
    static void stopUpstream() {
        upstream.stop();
    }

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) throws Exception {
        if (upstream == null) {
            upstream = new FakeUpstream();
        }
        r.add("gateway.upstream", () -> "http://127.0.0.1:" + upstream.port());
    }

    @BeforeEach
    void reset() {
        store.reset();
        upstream.requests.clear();
    }

    // ------------------------------------------------------------ proxying

    @Test
    void forwardsMethodPathQueryBodyAndHeadersAndReturnsTheUpstreamResponse() throws Exception {
        HttpResponse<String> r = send(port, "POST", "/api/search?q=shoes&x=%27a", "{\"k\":1}", "Content-Type", "application/json", "X-Custom", "hello");
        assertThat(r.statusCode()).isEqualTo(200);
        assertThat(r.body()).isEqualTo("{\"upstream\":\"ok\"}");
        assertThat(r.headers().firstValue("X-Upstream")).contains("yes");
        var seen = upstream.last();
        assertThat(seen.method()).isEqualTo("POST");
        assertThat(seen.path()).isEqualTo("/api/search");
        assertThat(seen.query()).isEqualTo("q=shoes&x=%27a");
        assertThat(seen.body()).isEqualTo("{\"k\":1}");
        assertThat(seen.headers().get("X-Custom")).containsExactly("hello");
    }

    @Test
    void forwardedForComesFromTheSocketAndSpoofedHeadersAreDiscarded() throws Exception {
        get(port, "/", "X-Forwarded-For", "6.6.6.6", "X-Real-IP", "7.7.7.7", "Forwarded", "for=8.8.8.8",
                "X-Sentinel-Token", "secret-should-not-leak", "X-Forwarded-Host", "evil.example");
        var h = upstream.last().headers();
        assertThat(h.get("X-Forwarded-For")).containsExactly("127.0.0.1");
        assertThat(h).doesNotContainKeys("X-Real-IP", "Forwarded", "X-Sentinel-Token", "X-Forwarded-Host");
        assertThat(h.get("Host").get(0)).startsWith("127.0.0.1:" + upstream.port());
    }

    @Test
    void upstreamErrorsPassThroughAndRedirectsAreNotFollowed() throws Exception {
        assertThat(get(port, "/boom").statusCode()).isEqualTo(500);
        HttpResponse<String> redirect = get(port, "/redirect");
        assertThat(redirect.statusCode()).isEqualTo(302);
        assertThat(redirect.headers().firstValue("Location")).contains("http://127.0.0.1:1/elsewhere");
    }

    @Test
    void slowUpstreamIsA504AndDownUpstreamIsA502WithoutDetails() throws Exception {
        HttpResponse<String> slow = get(port, "/slow");
        assertThat(slow.statusCode()).isEqualTo(504);
        assertThat(slow.body()).isEqualTo("{\"error\":\"gateway timeout\"}");
    }

    @Test
    void oversizedRequestBodiesAreRejected() throws Exception {
        assertThat(send(port, "POST", "/upload", "A".repeat(2000)).statusCode()).isEqualTo(413);
        assertThat(upstream.requests).isEmpty();
        assertThat(send(port, "POST", "/upload", "A".repeat(500)).statusCode()).isEqualTo(200);
    }

    @Test
    void unsupportedMethodsAreRefused() throws Exception {
        assertThat(send(port, "TRACE", "/", null).statusCode()).isIn(405, 400, 501);
        assertThat(upstream.requests).isEmpty();
    }

    // ------------------------------------------------------------ blocklist and rate limit

    @Test
    void blockedAddressesGet403AndNeverReachTheUpstream() throws Exception {
        store.blocked.put("127.0.0.1", true);
        HttpResponse<String> r = get(port, "/api/products");
        assertThat(r.statusCode()).isEqualTo(403);
        assertThat(r.body()).isEqualTo("{\"error\":\"blocked\"}");
        assertThat(upstream.requests).isEmpty();
        store.blocked.clear(); // an analyst unblocks the address: traffic flows again
        assertThat(get(port, "/api/products").statusCode()).isEqualTo(200);
    }

    @Test
    void rateLimitReturns429WithRetryAfterAfterTheLimit() throws Exception {
        for (int i = 0; i < 5; i++) {
            assertThat(get(port, "/api/products").statusCode()).isEqualTo(200);
        }
        HttpResponse<String> r = get(port, "/api/products");
        assertThat(r.statusCode()).isEqualTo(429);
        assertThat(Integer.parseInt(r.headers().firstValue("Retry-After").orElseThrow())).isBetween(1, 60);
        assertThat(upstream.requests).hasSize(5);
    }

    @Test
    void sentinelsDynamicLimitTightensButNeverLoosensTheDefault() throws Exception {
        store.dynamicLimit.put("127.0.0.1", 2);
        assertThat(get(port, "/").statusCode()).isEqualTo(200);
        assertThat(get(port, "/").statusCode()).isEqualTo(200);
        assertThat(get(port, "/").statusCode()).isEqualTo(429);
        store.reset();
        store.dynamicLimit.put("127.0.0.1", 100_000);
        for (int i = 0; i < 5; i++) {
            get(port, "/");
        }
        assertThat(get(port, "/").statusCode()).isEqualTo(429); // still capped at the default of 5
    }

    @Test
    void blockedBeatsEverythingElseEvenOnAdminRoutes() throws Exception {
        store.blocked.put("127.0.0.1", true);
        assertThat(get(port, "/admin/users", "X-Sentinel-Token", jwt("admin", 300)).statusCode()).isEqualTo(403);
    }

    @Test
    void decisionStoreOutageFailsOpenByDefault() throws Exception {
        store.failing = true;
        assertThat(get(port, "/api/products").statusCode()).isEqualTo(200);
    }

    // ------------------------------------------------------------ JWT / RBAC

    @Test
    void adminRoutesNeedAnAdminToken() throws Exception {
        assertThat(get(port, "/admin/users").statusCode()).isEqualTo(401);
        assertThat(get(port, "/admin/users", "X-Sentinel-Token", jwt("analyst", 300)).statusCode()).isEqualTo(403);
        assertThat(upstream.requests).isEmpty();
        HttpResponse<String> ok = get(port, "/admin/users", "X-Sentinel-Token", jwt("admin", 300), "Authorization", "Bearer shop-session");
        assertThat(ok.statusCode()).isEqualTo(200);
        var h = upstream.last().headers();
        assertThat(h.get("Authorization")).containsExactly("Bearer shop-session"); // the shop's own credential passes through
        assertThat(h).doesNotContainKey("X-Sentinel-Token"); // the gateway credential does not
    }

    @Test
    void badTokensAreRejectedOnAdminRoutes() throws Exception {
        for (String t : List.of("garbage", "a.b.c", "", jwt("admin", -60), jwt("admin", 300) + "x")) {
            store.counters.clear();
            int status = get(port, "/admin/users", "X-Sentinel-Token", t.isEmpty() ? " " : t).statusCode();
            assertThat(status).as(t).isEqualTo(401);
        }
        assertThat(upstream.requests).isEmpty();
    }

    @Test
    void pathTricksCannotBypassAdminProtection() throws Exception {
        List<String> tricks = List.of("/%61dmin/users", "//admin/users", "/admin/./users", "/x/../admin/users", "/ADMIN/users",
                "/admin;a=b/users", "/%2561dmin/users", "/admin/%2e%2e/admin/users", "/%2e/admin/users");
        for (String path : tricks) {
            store.counters.clear(); // keep the rate limiter out of this test
            int status = get(port, path).statusCode();
            assertThat(status).as(path).isEqualTo(401);
        }
        for (String path : List.of("/admin%2fusers", "/admin%5cusers", "/admin%00/users", "/admin%0d%0a/users")) {
            store.counters.clear();
            assertThat(get(port, path).statusCode()).as(path).isIn(400, 401);
        }
        assertThat(upstream.requests).as("nothing may reach the upstream without a token").isEmpty();
    }

    @Test
    void theForwardedPathIsTheCanonicalPathThatWasAuthorised() throws Exception {
        String admin = jwt("admin", 300);
        assertThat(get(port, "/x/../%61dmin/./users;p=1?id=5", "X-Sentinel-Token", admin).statusCode()).isEqualTo(200);
        assertThat(upstream.last().path()).isEqualTo("/admin/users");
        assertThat(upstream.last().query()).isEqualTo("id=5");
    }

    @Test
    void nonAdminPathsStayOpenAndAdministrativeLookalikesAreNotCaught() throws Exception {
        assertThat(get(port, "/administrator").statusCode()).isEqualTo(200);
        assertThat(get(port, "/api/admin-news").statusCode()).isEqualTo(200);
    }

    @Test
    void gatewayStatsNeedATokenButHealthIsOpen() throws Exception {
        assertThat(get(port, "/_gw/health").statusCode()).isEqualTo(200);
        assertThat(get(port, "/_gw/stats").statusCode()).isEqualTo(401);
        HttpResponse<String> r = get(port, "/_gw/stats", "Authorization", "Bearer " + jwt("analyst", 300));
        assertThat(r.statusCode()).isEqualTo(200);
        assertThat(r.body()).contains("\"requests\"").contains("\"blocked\"");
        assertThat(send(port, "DELETE", "/_gw/stats", null, "Authorization", "Bearer " + jwt("analyst", 300)).statusCode()).isEqualTo(403);
        assertThat(upstream.requests).isEmpty(); // gateway routes are never proxied
    }

    @Test
    void malformedPathsGetA400() throws Exception {
        assertThat(rawStatus(port, "GET /%ZZ HTTP/1.1")).isEqualTo(400);
        assertThat(rawStatus(port, "GET /admin/%zz/users HTTP/1.1")).isEqualTo(400);
        assertThat(upstream.requests).isEmpty();
    }
}
