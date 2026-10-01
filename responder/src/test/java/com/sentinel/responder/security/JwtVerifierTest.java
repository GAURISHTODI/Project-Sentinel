package com.sentinel.responder.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.sentinel.responder.GatewayProperties;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class JwtVerifierTest {
    static final String SECRET = "unit-test-secret-of-at-least-32-chars!!";
    JwtVerifier verifier;

    static GatewayProperties props(String secret) {
        return new GatewayProperties("http://x", secret, "sentinel", 300, true, 1024, 1024, 1000,
                List.of("/admin"), new GatewayProperties.Redis("r", 6379, "", 100));
    }

    @BeforeEach
    void setUp() {
        verifier = new JwtVerifier(props(SECRET));
        verifier.init();
    }

    static String token(String secret, String issuer, String role, Long expInSeconds, boolean sub) {
        var b = Jwts.builder().issuer(issuer).id(UUID.randomUUID().toString()).issuedAt(new Date());
        if (sub) {
            b.subject("alice");
        }
        if (role != null) {
            b.claim("role", role);
        }
        if (expInSeconds != null) {
            b.expiration(new Date(System.currentTimeMillis() + expInSeconds * 1000));
        }
        return b.signWith(Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8)), Jwts.SIG.HS256).compact();
    }

    @Test
    void acceptsAValidToken() {
        var p = verifier.verify(token(SECRET, "sentinel", "admin", 300L, true));
        assertThat(p).isPresent();
        assertThat(p.get().subject()).isEqualTo("alice");
        assertThat(p.get().isAdmin()).isTrue();
        assertThat(verifier.verify(token(SECRET, "sentinel", "analyst", 300L, true)).get().isAdmin()).isFalse();
    }

    @Test
    void rejectsEveryKindOfBadToken() {
        String otherSecret = "a-completely-different-secret-value-xyz";
        String noneAlg = Jwts.builder().issuer("sentinel").subject("alice").claim("role", "admin")
                .expiration(new Date(System.currentTimeMillis() + 300_000)).compact();
        String hs512 = Jwts.builder().issuer("sentinel").subject("alice").claim("role", "admin")
                .expiration(new Date(System.currentTimeMillis() + 300_000))
                .signWith(Keys.hmacShaKeyFor((SECRET + SECRET).getBytes(StandardCharsets.UTF_8)), Jwts.SIG.HS512).compact();
        List<String> bad = List.of(
                token(otherSecret, "sentinel", "admin", 300L, true),
                token(SECRET, "sentinel", "admin", -60L, true),
                token(SECRET, "sentinel", "admin", null, true),
                token(SECRET, "sentinel", null, 300L, true),
                token(SECRET, "sentinel", "superuser", 300L, true),
                token(SECRET, "evil", "admin", 300L, true),
                token(SECRET, "sentinel", "admin", 300L, false),
                noneAlg, hs512, "", "   ", "garbage", "a.b.c", "Bearer x", "x".repeat(5000));
        for (String t : bad) {
            assertThat(verifier.verify(t)).as(t.length() > 40 ? t.substring(0, 40) : t).isEmpty();
        }
        assertThat(verifier.verify(null)).isEmpty();
    }

    @Test
    void refusesToStartWithAWeakOrMissingSecret() {
        assertThatThrownBy(() -> new JwtVerifier(props("")).init()).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new JwtVerifier(props("too-short")).init()).isInstanceOf(IllegalStateException.class);
    }
}
