package com.sentinel.shop.web;

import com.sentinel.shop.ShopProperties;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Orders (IDOR in v1), admin data (missing authorization in v1), debug config and file download. */
@RestController
public class OrderAdminController {
    private final JdbcTemplate jdbc;
    private final ShopProperties props;
    private final Sessions sessions;

    public OrderAdminController(JdbcTemplate jdbc, ShopProperties props, Sessions sessions) {
        this.jdbc = jdbc;
        this.props = props;
        this.sessions = sessions;
    }

    @GetMapping("/api/orders")
    public ResponseEntity<?> myOrders(@RequestHeader(value = "Authorization", required = false) String auth) {
        var who = sessions.resolve(auth);
        if (who.isEmpty()) {
            return ResponseEntity.status(401).body(Map.of("error", "authentication required"));
        }
        return ResponseEntity.ok(Db.rows(jdbc,
                "SELECT id, product_id, quantity, address, total FROM orders WHERE user_id = ? ORDER BY id", who.get().userId()));
    }

    @GetMapping("/api/orders/{id}")
    public ResponseEntity<?> order(@PathVariable long id, @RequestHeader(value = "Authorization", required = false) String auth) {
        if (!props.secure()) {
            // v1 VULNERABLE (F-09): insecure direct object reference. No login and no ownership check:
            // any order, with its delivery address, can be read by counting ids.
            var rows = Db.rows(jdbc, "SELECT id, user_id, product_id, quantity, address, total FROM orders WHERE id = ?", id);
            return rows.isEmpty() ? ResponseEntity.notFound().build() : ResponseEntity.ok(rows.get(0));
        }
        var who = sessions.resolve(auth);
        if (who.isEmpty()) {
            return ResponseEntity.status(401).body(Map.of("error", "authentication required"));
        }
        var rows = Db.rows(jdbc, "SELECT id, user_id, product_id, quantity, address, total FROM orders WHERE id = ?", id);
        // v2 FIXED: only the owner (or an admin) may read an order; others get the same 404 as a missing id
        if (rows.isEmpty() || (!who.get().admin() && ((Number) rows.get(0).get("user_id")).longValue() != who.get().userId())) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(rows.get(0));
    }

    @GetMapping("/admin/users")
    public ResponseEntity<?> adminUsers(@RequestHeader(value = "Authorization", required = false) String auth) {
        if (props.secure()) {
            var who = sessions.resolve(auth);
            if (who.isEmpty()) {
                return ResponseEntity.status(401).body(Map.of("error", "authentication required"));
            }
            if (!who.get().admin()) {
                return ResponseEntity.status(403).body(Map.of("error", "forbidden"));
            }
            return ResponseEntity.ok(Db.rows(jdbc, "SELECT id, username, role, email FROM users ORDER BY id"));
        }
        // v1 VULNERABLE (F-10): broken access control, no authentication, and password hashes included
        return ResponseEntity.ok(Db.rows(jdbc, "SELECT id, username, password, role, email FROM users ORDER BY id"));
    }

    @GetMapping("/debug/config")
    public ResponseEntity<?> debugConfig() {
        if (props.secure()) {
            return ResponseEntity.notFound().build();
        }
        // v1 VULNERABLE (F-11): a debug endpoint left enabled that reveals configuration and credentials
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("version", props.version());
        out.put("javaVersion", System.getProperty("java.version"));
        out.put("filesDir", props.filesDir());
        out.put("datasourceUrl", "jdbc:h2:mem:shop");
        out.put("datasourceUser", "sa");
        out.put("datasourcePassword", "lab-only-not-a-real-secret");
        out.put("adminDefaultLogin", "admin / admin");
        return ResponseEntity.ok(out);
    }

    @GetMapping("/api/files")
    public ResponseEntity<?> file(@RequestParam String name) throws IOException {
        if (!props.secure()) {
            // v1 VULNERABLE (F-12): path traversal. The file name is joined onto the directory unchecked.
            File f = new File(props.filesDir(), name);
            if (!f.isFile()) {
                return ResponseEntity.status(404).body(Map.of("error", "file not found: " + f.getPath()));
            }
            return ResponseEntity.ok(Files.readString(f.toPath(), StandardCharsets.UTF_8));
        }
        Path base = Path.of(props.filesDir()).toAbsolutePath().normalize();
        Path target = base.resolve(name).normalize();
        // v2 FIXED: the resolved path must stay inside the directory, and only .txt files are served
        if (name.length() > 100 || !target.startsWith(base) || !target.toString().endsWith(".txt") || !Files.isRegularFile(target)) {
            return ResponseEntity.status(404).body(Map.of("error", "not found"));
        }
        return ResponseEntity.ok(Files.readString(target, StandardCharsets.UTF_8));
    }

    /** Used by tests. */
    List<Map<String, Object>> allUsers() {
        return Db.rows(jdbc, "SELECT id, username FROM users");
    }
}
