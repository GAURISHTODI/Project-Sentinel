package com.sentinel.shop;

import static com.sentinel.shop.ShopTestSupport.JSON;
import static com.sentinel.shop.ShopTestSupport.bearer;
import static com.sentinel.shop.ShopTestSupport.login;
import static com.sentinel.shop.ShopTestSupport.token;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import com.sentinel.shop.events.LocalEventSink;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.MockMvcPrint;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/** The same attacks as the v1 tests, against v2: every one must now fail. */
@SpringBootTest(properties = {
    "shop.version=v2", "spring.datasource.url=jdbc:h2:mem:v2test;DB_CLOSE_DELAY=-1",
    "shop.admin-password=Lab-Admin-Passw0rd-For-Tests"})
@AutoConfigureMockMvc(print = MockMvcPrint.NONE)
class V2FixesTest {
    static final String ADMIN_PW = "Lab-Admin-Passw0rd-For-Tests";
    @Autowired MockMvc mvc;
    @Autowired JdbcTemplate jdbc;
    @Autowired LocalEventSink sink;
    @Autowired com.sentinel.shop.web.LoginGuard guard;

    @org.junit.jupiter.api.BeforeEach
    void resetLimiter() {
        guard.reset(); // all requests share one client IP in MockMvc
    }

    private String body(MvcResult r) throws Exception {
        return r.getResponse().getContentAsString(StandardCharsets.UTF_8);
    }

    @Test
    void f01_sqlInjectionNoLongerBypassesLogin() throws Exception {
        for (String user : new String[] {"admin'--", "x' OR '1'='1' --", "'"}) {
            assertThat(login(mvc, user, "whatever").getResponse().getStatus()).as(user).isEqualTo(401);
        }
        assertThat(body(login(mvc, "admin'--", "x"))).isEqualTo("{\"error\":\"invalid credentials\"}");
    }

    @Test
    void f02_loginIsRateLimitedAndAccountsLockOut() throws Exception {
        for (int i = 0; i < 5; i++) {
            assertThat(login(mvc, "carol", "wrong-" + i).getResponse().getStatus()).isEqualTo(401);
        }
        // the right password is refused too: the account is locked after 5 consecutive failures
        assertThat(login(mvc, "carol", "qwerty123").getResponse().getStatus()).isEqualTo(423);
    }

    @Test
    void f02_perIpRateLimitTriggers() throws Exception {
        int limited = 0;
        for (int i = 0; i < 14; i++) {
            if (login(mvc, "ghost-" + i, "x").getResponse().getStatus() == 429) {
                limited++;
            }
        }
        assertThat(limited).isGreaterThanOrEqualTo(3);
    }

    @Test
    void f03_passwordsAreBcrypt() {
        String hash = jdbc.queryForObject("SELECT password FROM users WHERE username = 'admin'", String.class);
        assertThat(hash).startsWith("$2a$");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM users WHERE LENGTH(password) = 32", Integer.class)).isZero();
    }

    @Test
    void f04_errorsAreGeneric() throws Exception {
        assertThat(body(login(mvc, "nobody-here", "x"))).isEqualTo(body(login(mvc, "bob", "x")));
    }

    @Test
    void f05_tokensAreRandomAndForgeriesFail() throws Exception {
        String forged = Base64.getEncoder().encodeToString("alice:admin".getBytes(StandardCharsets.UTF_8));
        assertThat(mvc.perform(get("/api/orders").header("Authorization", bearer(forged))).andReturn()
                .getResponse().getStatus()).isEqualTo(401);
        String real = token(mvc, "alice", "sunshine");
        assertThat(real).matches("[0-9a-f]{64}");
        assertThat(mvc.perform(get("/api/orders").header("Authorization", bearer(real))).andReturn()
                .getResponse().getStatus()).isEqualTo(200);
    }

    @Test
    void f06_searchInjectionReturnsNothing() throws Exception {
        for (String q : new String[] {"zzz' UNION SELECT id, username, 0, password FROM users --", "' OR 1=1 --"}) {
            MvcResult r = mvc.perform(get("/api/search").param("q", q)).andReturn();
            assertThat(r.getResponse().getStatus()).isEqualTo(200);
            assertThat(body(r)).isEqualTo("[]");
        }
        assertThat(body(mvc.perform(get("/api/search").param("q", "shoes")).andReturn())).contains("Trail Running Shoes");
    }

    @Test
    void f07_reflectedInputIsEncoded() throws Exception {
        String html = body(mvc.perform(get("/search").param("q", "<script>alert(1)</script>")).andReturn());
        assertThat(html).doesNotContain("<script>alert(1)</script>").contains("&lt;script&gt;");
    }

    @Test
    void f08_storedCommentsAreEncodedOnOutput() throws Exception {
        String xss = "<img src=x onerror=alert(1)>";
        mvc.perform(post("/api/products/2/comments").contentType(MediaType.APPLICATION_JSON)
                .content(JSON.writeValueAsString(Map.of("author", "eve", "body", xss)))).andReturn();
        String html = body(mvc.perform(get("/products/2")).andReturn());
        assertThat(html).doesNotContain(xss).contains("&lt;img src=x onerror=alert(1)&gt;");
        MvcResult tooLong = mvc.perform(post("/api/products/2/comments").contentType(MediaType.APPLICATION_JSON)
                .content(JSON.writeValueAsString(Map.of("author", "eve", "body", "A".repeat(501))))).andReturn();
        assertThat(tooLong.getResponse().getStatus()).isEqualTo(400);
    }

    @Test
    void f09_ordersAreProtectedByOwnership() throws Exception {
        assertThat(mvc.perform(get("/api/orders/1")).andReturn().getResponse().getStatus()).isEqualTo(401);
        String alice = token(mvc, "alice", "sunshine");
        assertThat(mvc.perform(get("/api/orders/1").header("Authorization", bearer(alice))).andReturn().getResponse().getStatus()).isEqualTo(200);
        assertThat(mvc.perform(get("/api/orders/3").header("Authorization", bearer(alice))).andReturn().getResponse().getStatus()).isEqualTo(404);
        assertThat(mvc.perform(get("/api/orders/6").header("Authorization", bearer(alice))).andReturn().getResponse().getStatus()).isEqualTo(404);
        String admin = token(mvc, "admin", ADMIN_PW);
        assertThat(mvc.perform(get("/api/orders/3").header("Authorization", bearer(admin))).andReturn().getResponse().getStatus()).isEqualTo(200);
    }

    @Test
    void f10_adminEndpointRequiresTheAdminRole() throws Exception {
        assertThat(mvc.perform(get("/admin/users")).andReturn().getResponse().getStatus()).isEqualTo(401);
        String alice = token(mvc, "bob", "letmein");
        assertThat(mvc.perform(get("/admin/users").header("Authorization", bearer(alice))).andReturn().getResponse().getStatus()).isEqualTo(403);
        String admin = token(mvc, "admin", ADMIN_PW);
        MvcResult r = mvc.perform(get("/admin/users").header("Authorization", bearer(admin))).andReturn();
        assertThat(r.getResponse().getStatus()).isEqualTo(200);
        assertThat(body(r)).doesNotContain("password");
    }

    @Test
    void f10_defaultAdminPasswordNoLongerWorks() throws Exception {
        assertThat(login(mvc, "admin", "admin").getResponse().getStatus()).isEqualTo(401);
    }

    @Test
    void f11_debugEndpointIsGone() throws Exception {
        assertThat(mvc.perform(get("/debug/config")).andReturn().getResponse().getStatus()).isEqualTo(404);
    }

    @Test
    void f12_pathTraversalIsBlocked() throws Exception {
        for (String name : new String[] {"../secret.txt", "..\\secret.txt", "/etc/passwd", "catalog.txt/../../secret.txt"}) {
            assertThat(mvc.perform(get("/api/files").param("name", name)).andReturn().getResponse().getStatus()).as(name).isEqualTo(404);
        }
        MvcResult ok = mvc.perform(get("/api/files").param("name", "catalog.txt")).andReturn();
        assertThat(ok.getResponse().getStatus()).isEqualTo(200);
        assertThat(body(ok)).contains("Sentinel Shop catalogue");
    }

    @Test
    void f13_securityHeadersPresentAndNoWildcardCors() throws Exception {
        MvcResult r = mvc.perform(get("/api/health")).andReturn();
        assertThat(r.getResponse().getHeader("X-Frame-Options")).isEqualTo("DENY");
        assertThat(r.getResponse().getHeader("X-Content-Type-Options")).isEqualTo("nosniff");
        assertThat(r.getResponse().getHeader("Content-Security-Policy")).contains("default-src 'self'");
        assertThat(r.getResponse().getHeader("Access-Control-Allow-Origin")).isNull();
        assertThat(r.getResponse().getHeader("X-Powered-By")).isNull();
    }

    @Test
    void f14_errorsAreGeneric() throws Exception {
        MvcResult r = mvc.perform(get("/api/orders/not-a-number")).andReturn();
        assertThat(r.getResponse().getStatus()).isEqualTo(400);
        assertThat(body(r)).doesNotContain("Exception");
    }

    @Test
    void formEncodedLoginIsAlsoProtected() throws Exception {
        assertThat(mvc.perform(post("/api/login").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("username", "admin'--").param("password", "x")).andReturn().getResponse().getStatus()).isEqualTo(401);
        assertThat(mvc.perform(post("/api/login").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("username", "alice").param("password", "sunshine")).andReturn().getResponse().getStatus()).isEqualTo(200);
    }

    @Test
    void unknownRoutesAre404WithoutDetail() throws Exception {
        MvcResult r = mvc.perform(get("/.env")).andReturn();
        assertThat(r.getResponse().getStatus()).isEqualTo(404);
        assertThat(body(r)).isEqualTo("{\"error\":\"not found\"}");
    }

    @Test
    void authEventsStillRecordFailedAttempts() throws Exception {
        sink.authEvents().clear();
        login(mvc, "mallory", "bad");
        assertThat(sink.authEvents()).extracting(e -> e.username() + ":" + e.outcome()).containsExactly("mallory:failure");
    }
}
