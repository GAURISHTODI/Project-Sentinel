package com.sentinel.shop.web;

import com.sentinel.shop.ShopProperties;
import java.util.List;
import java.util.Map;
import org.springframework.dao.DataAccessException;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Products, search (SQLi + reflected XSS in v1) and comments (stored XSS in v1). */
@RestController
public class CatalogController {
    public record CommentRequest(String author, String body) {}

    private final JdbcTemplate jdbc;
    private final ShopProperties props;

    public CatalogController(JdbcTemplate jdbc, ShopProperties props) {
        this.jdbc = jdbc;
        this.props = props;
    }

    @GetMapping(value = "/", produces = MediaType.TEXT_HTML_VALUE)
    public String home() {
        StringBuilder sb = new StringBuilder("<h2>Products</h2><ul>");
        for (var p : Db.rows(jdbc, "SELECT id, name, price FROM products ORDER BY id")) {
            sb.append("<li><a href=\"/products/").append(p.get("id")).append("\">").append(Html.esc(p.get("name")))
                    .append("</a> - ").append(p.get("price")).append("</li>");
        }
        sb.append("</ul><form action=\"/search\" method=\"get\"><input name=\"q\"><button>Search</button></form>");
        return Html.page("Sentinel Shop (" + props.version() + ")", sb.toString());
    }

    @GetMapping("/api/health")
    public Map<String, String> health() {
        return Map.of("status", "ok", "version", props.version());
    }

    @GetMapping("/api/products")
    public List<Map<String, Object>> products() {
        return Db.rows(jdbc, "SELECT id, name, price, description FROM products ORDER BY id");
    }

    @GetMapping("/api/products/{id}")
    public ResponseEntity<Map<String, Object>> product(@PathVariable long id) {
        var rows = Db.rows(jdbc, "SELECT id, name, price, description FROM products WHERE id = ?", id);
        return rows.isEmpty() ? ResponseEntity.notFound().build() : ResponseEntity.ok(rows.get(0));
    }

    // ---------------------------------------------------------------- search (JSON)
    @GetMapping("/api/search")
    public ResponseEntity<?> searchApi(@RequestParam(defaultValue = "") String q) {
        if (props.secure()) {
            if (q.length() > 100) {
                return ResponseEntity.badRequest().body(Map.of("error", "query too long"));
            }
            return ResponseEntity.ok(Db.rows(jdbc,
                    "SELECT id, name, price, description FROM products WHERE LOWER(name) LIKE ?", "%" + q.toLowerCase() + "%"));
        }
        // v1 VULNERABLE (F-06): SQL injection by string concatenation, database errors returned verbatim
        // nosemgrep: java.spring.security.injection.tainted-sql-string.tainted-sql-string  -- intentional v1 finding F-06; v2 uses a bound parameter
        String sql = "SELECT id, name, price, description FROM products WHERE name LIKE '%" + q + "%'";
        try {
            return ResponseEntity.ok(Db.rows(jdbc, sql));
        } catch (DataAccessException e) {
            return ResponseEntity.status(500).body(Map.of("error", "Database error", "sql", sql, "detail", String.valueOf(e.getMessage())));
        }
    }

    // ---------------------------------------------------------------- search (HTML page)
    @GetMapping(value = "/search", produces = MediaType.TEXT_HTML_VALUE)
    public String searchPage(@RequestParam(defaultValue = "") String q) {
        if (props.secure()) {
            String safe = q.length() > 100 ? q.substring(0, 100) : q;
            var rows = Db.rows(jdbc, "SELECT id, name, price FROM products WHERE LOWER(name) LIKE ?", "%" + safe.toLowerCase() + "%");
            return Html.page("Search", "<p>Results for: " + Html.esc(safe) + "</p>" + list(rows, true));
        }
        // v1 VULNERABLE (F-07): the query is reflected into the page unescaped (reflected XSS),
        // and (F-06) concatenated into SQL.
        // nosemgrep: java.spring.security.injection.tainted-sql-string.tainted-sql-string  -- intentional v1 finding F-06 (F-07 page); v2 uses a bound parameter
        String sql = "SELECT id, name, price FROM products WHERE name LIKE '%" + q + "%'";
        try {
            return Html.page("Search", "<p>Results for: " + q + "</p>" + list(Db.rows(jdbc, sql), false));
        } catch (DataAccessException e) {
            return Html.page("Search", "<p>Results for: " + q + "</p><pre>" + e.getMessage() + "</pre>");
        }
    }

    private static String list(List<Map<String, Object>> rows, boolean escape) {
        StringBuilder sb = new StringBuilder("<ul>");
        for (var r : rows) {
            String name = String.valueOf(r.get("name"));
            sb.append("<li><a href=\"/products/").append(r.get("id")).append("\">")
                    .append(escape ? Html.esc(name) : name).append("</a></li>");
        }
        return sb.append("</ul>").toString();
    }

    // ---------------------------------------------------------------- product page with comments
    @GetMapping(value = "/products/{id}", produces = MediaType.TEXT_HTML_VALUE)
    public ResponseEntity<String> productPage(@PathVariable long id) {
        var rows = Db.rows(jdbc, "SELECT id, name, price, description FROM products WHERE id = ?", id);
        if (rows.isEmpty()) {
            return ResponseEntity.status(404).body(Html.page("Not found", "<p>No such product.</p>"));
        }
        var p = rows.get(0);
        StringBuilder body = new StringBuilder("<p>" + Html.esc(p.get("description")) + "</p><p>Price: " + p.get("price") + "</p><h3>Comments</h3><ul>");
        for (var c : Db.rows(jdbc, "SELECT author, body FROM comments WHERE product_id = ? ORDER BY id", id)) {
            // v1 VULNERABLE (F-08): stored comments are written into the page unescaped (stored XSS)
            String author = props.secure() ? Html.esc(c.get("author")) : String.valueOf(c.get("author"));
            String text = props.secure() ? Html.esc(c.get("body")) : String.valueOf(c.get("body"));
            body.append("<li><b>").append(author).append("</b>: ").append(text).append("</li>");
        }
        body.append("</ul>");
        return ResponseEntity.ok(Html.page(String.valueOf(p.get("name")), body.toString()));
    }

    @PostMapping("/api/products/{id}/comments")
    public ResponseEntity<Map<String, Object>> addComment(@PathVariable long id, @RequestBody CommentRequest req) {
        String author = req.author() == null ? "anonymous" : req.author();
        String body = req.body() == null ? "" : req.body();
        if (props.secure() && (author.length() > 64 || body.isBlank() || body.length() > 500)) {
            return ResponseEntity.badRequest().body(Map.of("error", "invalid comment"));
        }
        if (Db.rows(jdbc, "SELECT id FROM products WHERE id = ?", id).isEmpty()) {
            return ResponseEntity.status(404).body(Map.of("error", "no such product"));
        }
        jdbc.update("INSERT INTO comments (product_id, author, body) VALUES (?, ?, ?)", id,
                author.length() > 64 ? author.substring(0, 64) : author, body.length() > 2000 ? body.substring(0, 2000) : body);
        return ResponseEntity.status(201).body(Map.of("status", "created"));
    }
}
