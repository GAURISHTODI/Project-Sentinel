package com.sentinel.shop.web;

import com.sentinel.shop.ShopProperties;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * Session tokens.
 * v1 (VULNERABLE): the token is just base64("username:role"). Anyone can forge one for any user,
 *     including an admin, and the role inside the token is trusted.
 * v2 (FIXED): random 256-bit tokens stored server-side with an expiry; the role comes from the database.
 */
@Component
public class Sessions {
    public record Principal(long userId, String username, String role) {
        public boolean admin() {
            return "admin".equals(role);
        }
    }

    private record Entry(Principal principal, Instant expires) {}

    private static final long TTL_SECONDS = 1800;
    private final JdbcTemplate jdbc;
    private final ShopProperties props;
    private final SecureRandom random = new SecureRandom();
    private final Map<String, Entry> tokens = new ConcurrentHashMap<>();

    public Sessions(JdbcTemplate jdbc, ShopProperties props) {
        this.jdbc = jdbc;
        this.props = props;
    }

    public String issue(Principal p) {
        if (!props.secure()) {
            // v1 VULNERABLE: predictable, forgeable, role-carrying token
            return Base64.getEncoder().encodeToString((p.username() + ":" + p.role()).getBytes(StandardCharsets.UTF_8));
        }
        byte[] raw = new byte[32];
        random.nextBytes(raw);
        String token = HexFormat.of().formatHex(raw);
        tokens.put(token, new Entry(p, Instant.now().plusSeconds(TTL_SECONDS)));
        return token;
    }

    /** Resolve an "Authorization: Bearer ..." header to a principal, if valid. */
    public Optional<Principal> resolve(String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ") || authorization.length() > 600) {
            return Optional.empty();
        }
        String token = authorization.substring(7).trim();
        return props.secure() ? resolveSecure(token) : resolveWeak(token);
    }

    private Optional<Principal> resolveSecure(String token) {
        Entry e = tokens.get(token);
        if (e == null || e.expires().isBefore(Instant.now())) {
            tokens.remove(token);
            return Optional.empty();
        }
        return Optional.of(e.principal());
    }

    private Optional<Principal> resolveWeak(String token) {
        try {
            String[] parts = new String(Base64.getDecoder().decode(token), StandardCharsets.UTF_8).split(":", 2);
            if (parts.length != 2) {
                return Optional.empty();
            }
            Long id = jdbc.queryForObject("SELECT id FROM users WHERE username = ?", Long.class, parts[0]);
            return Optional.of(new Principal(id == null ? -1 : id, parts[0], parts[1])); // trusts the role in the token
        } catch (IllegalArgumentException | EmptyResultDataAccessException e) {
            return Optional.empty();
        }
    }
}
