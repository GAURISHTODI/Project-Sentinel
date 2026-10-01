package com.sentinel.shop.web;

import org.springframework.web.util.HtmlUtils;

/** Minimal HTML helpers. {@link #esc} is the output encoding that v2 applies and v1 omits. */
final class Html {
    private Html() {}

    static String esc(Object value) {
        return HtmlUtils.htmlEscape(String.valueOf(value));
    }

    static String page(String title, String body) {
        return "<!doctype html><html><head><meta charset=\"utf-8\"><title>" + esc(title)
                + "</title></head><body><h1>" + esc(title) + "</h1>"
                + "<nav><a href=\"/\">Home</a> | <a href=\"/search?q=\">Search</a></nav>" + body + "</body></html>";
    }
}
