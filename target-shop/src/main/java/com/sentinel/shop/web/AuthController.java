package com.sentinel.shop.web;

import com.sentinel.shop.ShopProperties;
import com.sentinel.shop.data.DataInitializer;
import com.sentinel.shop.events.EventSink;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;
import org.springframework.dao.DataAccessException;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {
    public record LoginRequest(String username, String password) {}

    private static final BCryptPasswordEncoder BCRYPT = new BCryptPasswordEncoder(10);
    /** Compared against when the user does not exist, so timing does not reveal valid usernames. */
    private static final String DUMMY_HASH = BCRYPT.encode("dummy-password-for-timing");

    private final JdbcTemplate jdbc;
    private final ShopProperties props;
    private final Sessions sessions;
    private final LoginGuard guard;
    private final EventSink events;

    public AuthController(JdbcTemplate jdbc, ShopProperties props, Sessions sessions, LoginGuard guard, EventSink events) {
        this.jdbc = jdbc;
        this.props = props;
        this.sessions = sessions;
        this.guard = guard;
        this.events = events;
    }

    @PostMapping("/api/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody LoginRequest req, HttpServletRequest http) {
        String ip = ClientIp.resolve(http, props);
        String username = req.username() == null ? "" : req.username();
        String password = req.password() == null ? "" : req.password();
        ResponseEntity<Map<String, Object>> response = props.secure()
                ? loginSecure(username, password, ip)
                : loginVulnerable(username, password);
        boolean ok = response.getStatusCode().is2xxSuccessful();
        events.auth(new EventSink.AuthEvent(
                System.currentTimeMillis() / 1000.0, ip, username, ok ? "success" : "failure",
                http.getHeader("User-Agent")));
        return response;
    }

    // ---------------------------------------------------------------- v1: VULNERABLE
    // F-01 SQL injection (string concatenation), F-02 no rate limit / lockout,
    // F-03 weak MD5 password storage, F-04 user enumeration + verbose errors, F-05 forgeable token.
    private ResponseEntity<Map<String, Object>> loginVulnerable(String username, String password) {
        String sql = "SELECT id, username, role FROM users WHERE username = '" + username
                + "' AND password = '" + DataInitializer.md5(password) + "'";
        try {
            List<Map<String, Object>> rows = Db.rows(jdbc, sql);
            if (!rows.isEmpty()) {
                var row = rows.get(0);
                var principal = new Sessions.Principal(((Number) row.get("id")).longValue(),
                        String.valueOf(row.get("username")), String.valueOf(row.get("role")));
                return ResponseEntity.ok(Map.of("token", sessions.issue(principal),
                        "username", principal.username(), "role", principal.role()));
            }
            Integer known = jdbc.queryForObject("SELECT COUNT(*) FROM users WHERE username = ?", Integer.class, username);
            String reason = known != null && known > 0 ? "wrong password" : "unknown user";
            return ResponseEntity.status(401).body(Map.of("error", "Login failed for '" + username + "': " + reason));
        } catch (DataAccessException e) {
            // verbose error: leaks the SQL statement and database error text
            return ResponseEntity.status(500).body(Map.of("error", "Database error", "sql", sql, "detail", String.valueOf(e.getMessage())));
        }
    }

    // ---------------------------------------------------------------- v2: FIXED
    // Parameterised query, BCrypt, per-IP rate limit and account lockout, random server-side token,
    // identical generic error for every failure.
    private ResponseEntity<Map<String, Object>> loginSecure(String username, String password, String ip) {
        if (username.length() > 64 || password.length() > 128) {
            return ResponseEntity.status(400).body(Map.of("error", "invalid request"));
        }
        switch (guard.check(ip, username)) {
            case RATE_LIMITED -> {
                return ResponseEntity.status(429).body(Map.of("error", "too many attempts, try again later"));
            }
            case LOCKED -> {
                return ResponseEntity.status(423).body(Map.of("error", "account temporarily locked"));
            }
            default -> { }
        }
        List<Map<String, Object>> rows = Db.rows(jdbc, "SELECT id, username, role, password FROM users WHERE username = ?", username);
        String hash = rows.isEmpty() ? DUMMY_HASH : String.valueOf(rows.get(0).get("password"));
        boolean matches = BCRYPT.matches(password, hash);
        if (rows.isEmpty() || !matches) {
            guard.failure(username);
            return ResponseEntity.status(401).body(Map.of("error", "invalid credentials"));
        }
        guard.success(username);
        var row = rows.get(0);
        var principal = new Sessions.Principal(((Number) row.get("id")).longValue(),
                String.valueOf(row.get("username")), String.valueOf(row.get("role")));
        return ResponseEntity.ok(Map.of("token", sessions.issue(principal), "username", principal.username(), "role", principal.role()));
    }
}
