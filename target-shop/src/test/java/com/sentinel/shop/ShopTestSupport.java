package com.sentinel.shop;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/** Shared helpers for the v1/v2 test classes. */
final class ShopTestSupport {
    static final ObjectMapper JSON = new ObjectMapper();

    private ShopTestSupport() {}

    static MvcResult login(MockMvc mvc, String username, String password) throws Exception {
        return mvc.perform(post("/api/login").contentType(MediaType.APPLICATION_JSON)
                .content(JSON.writeValueAsString(Map.of("username", username, "password", password)))
                .header("User-Agent", "unit-test")).andReturn();
    }

    static String token(MockMvc mvc, String username, String password) throws Exception {
        MvcResult r = login(mvc, username, password);
        if (r.getResponse().getStatus() != 200) {
            throw new IllegalStateException("login failed for " + username + ": " + r.getResponse().getContentAsString());
        }
        JsonNode n = JSON.readTree(r.getResponse().getContentAsString());
        return n.get("token").asText();
    }

    static String bearer(String token) {
        return "Bearer " + token;
    }
}
