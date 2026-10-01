package com.sentinel.shop.web;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;

/** Tiny query helper that returns rows with lower-case keys (H2 upper-cases column names). */
final class Db {
    private Db() {}

    static List<Map<String, Object>> rows(JdbcTemplate jdbc, String sql, Object... args) {
        return jdbc.query(sql, (rs, i) -> {
            var md = rs.getMetaData();
            Map<String, Object> row = new LinkedHashMap<>();
            for (int c = 1; c <= md.getColumnCount(); c++) {
                row.put(md.getColumnLabel(c).toLowerCase(), rs.getObject(c));
            }
            return row;
        }, args);
    }
}
