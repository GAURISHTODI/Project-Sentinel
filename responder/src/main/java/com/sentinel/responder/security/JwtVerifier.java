package com.sentinel.responder.security;

import com.sentinel.responder.GatewayProperties;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Optional;
import java.util.Set;
import javax.crypto.SecretKey;
import org.springframework.stereotype.Component;

/**
 * Validates tokens issued by the Sentinel API. Only HS256 is accepted (the algorithm is checked
 * explicitly, so "alg: none" and HS384/HS512 variants are rejected), the issuer must match, the token must
 * expire, and it must carry a subject and a known role.
 */
@Component
public class JwtVerifier {
    public record Principal(String subject, String role) {
        public boolean isAdmin() {
            return "admin".equals(role);
        }
    }

    private static final Set<String> ROLES = Set.of("analyst", "admin");
    private static final int MIN_SECRET_BYTES = 32;

    private final GatewayProperties props;
    private SecretKey key;

    public JwtVerifier(GatewayProperties props) {
        this.props = props;
    }

    @PostConstruct
    void init() {
        byte[] secret = props.jwtSecret().getBytes(StandardCharsets.UTF_8);
        if (secret.length < MIN_SECRET_BYTES) {
            throw new IllegalStateException("gateway.jwt-secret (GATEWAY_JWT_SECRET) must be at least 32 characters");
        }
        this.key = Keys.hmacShaKeyFor(secret);
    }

    public Optional<Principal> verify(String token) {
        if (token == null || token.isBlank() || token.length() > 4096) {
            return Optional.empty();
        }
        try {
            Jws<Claims> jws = Jwts.parser().verifyWith(key).requireIssuer(props.issuer()).build().parseSignedClaims(token.trim());
            if (!"HS256".equals(jws.getHeader().getAlgorithm())) {
                return Optional.empty();
            }
            Claims c = jws.getPayload();
            Date exp = c.getExpiration();
            String role = c.get("role", String.class);
            if (exp == null || c.getSubject() == null || role == null || !ROLES.contains(role)) {
                return Optional.empty();
            }
            return Optional.of(new Principal(c.getSubject(), role));
        } catch (JwtException | IllegalArgumentException e) {
            return Optional.empty();
        }
    }
}
