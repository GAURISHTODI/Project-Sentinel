package com.sentinel.shop.data;

import com.sentinel.shop.ShopProperties;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Seeds the lab data. v1 stores unsalted MD5 password hashes and a guessable admin password;
 * v2 stores BCrypt hashes and takes the admin password from configuration (or a random one).
 */
@Component
public class DataInitializer implements ApplicationRunner {
    private static final Logger log = LoggerFactory.getLogger(DataInitializer.class);

    private final JdbcTemplate jdbc;
    private final ShopProperties props;

    public DataInitializer(JdbcTemplate jdbc, ShopProperties props) {
        this.jdbc = jdbc;
        this.props = props;
    }

    /** Weak lab credentials on purpose; they are what the Hydra wordlist in lab/ contains. */
    public static final String[][] USERS = {
        {"alice", "sunshine", "customer", "alice@shop.test"},
        {"bob", "letmein", "customer", "bob@shop.test"},
        {"carol", "qwerty123", "customer", "carol@shop.test"},
    };

    @Override
    public void run(ApplicationArguments args) {
        String adminPassword = props.secure() ? secureAdminPassword() : "admin";
        insertUser("admin", adminPassword, "admin", "admin@shop.test");
        for (String[] u : USERS) {
            insertUser(u[0], u[1], u[2], u[3]);
        }
        String[][] products = {
            {"Trail Running Shoes", "89.90", "Lightweight shoes for rough terrain."},
            {"Noise-Cancelling Headphones", "199.00", "Over-ear, 30 hour battery."},
            {"Stainless Water Bottle", "24.50", "Keeps drinks cold for 24 hours."},
            {"Mechanical Keyboard", "129.99", "Hot-swappable switches, aluminium case."},
            {"Backpack 28L", "64.00", "Water resistant, laptop sleeve."},
        };
        for (String[] p : products) {
            jdbc.update("INSERT INTO products (name, price, description) VALUES (?, ?, ?)", p[0], p[1], p[2]);
        }
        // alice: orders 1-2, bob: 3, carol: 4-5, admin: 6 (the IDOR finding reads other people's orders)
        long[][] orders = {{2, 1, 1, 8990}, {2, 3, 2, 4900}, {3, 2, 1, 19900}, {4, 4, 1, 12999}, {4, 5, 1, 6400}, {1, 2, 3, 59700}};
        String[] addresses = {
            "12 Lakeview Rd, Springfield", "12 Lakeview Rd, Springfield", "98 Hill St, Rivertown",
            "5 Elm Ave, Fairview", "5 Elm Ave, Fairview", "1 Admin Plaza, Capital City",
        };
        for (int i = 0; i < orders.length; i++) {
            jdbc.update(
                    "INSERT INTO orders (user_id, product_id, quantity, address, total) VALUES (?, ?, ?, ?, ?)",
                    orders[i][0], orders[i][1], orders[i][2], addresses[i], orders[i][3] / 100.0);
        }
        jdbc.update("INSERT INTO comments (product_id, author, body) VALUES (1, 'bob', 'Great grip on wet rocks.')");
        log.info("seeded lab data (version {})", props.version());
    }

    private String secureAdminPassword() {
        if (!props.adminPassword().isBlank()) {
            return props.adminPassword();
        }
        byte[] raw = new byte[18];
        new SecureRandom().nextBytes(raw);
        String random = HexFormat.of().formatHex(raw);
        log.info("v2 admin password is random for this run (set SHOP_ADMIN_PASSWORD to fix it)");
        return random;
    }

    private void insertUser(String username, String password, String role, String email) {
        String stored = props.secure() ? new BCryptPasswordEncoder(10).encode(password) : md5(password);
        jdbc.update("INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)", username, stored, role, email);
    }

    /** v1 password storage: fast, unsalted MD5 (a finding on purpose). */
    public static String md5(String s) {
        try {
            // nosemgrep: java.lang.security.audit.crypto.use-of-md5.use-of-md5  -- intentional v1 password storage (F-03); v2 uses BCrypt
            return HexFormat.of().formatHex(MessageDigest.getInstance("MD5").digest(s.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
