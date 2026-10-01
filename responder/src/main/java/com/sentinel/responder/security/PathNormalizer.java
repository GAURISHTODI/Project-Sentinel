package com.sentinel.responder.security;

import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Turns the raw request path into the single canonical form that is BOTH authorised and forwarded, so the
 * gateway and the application can never disagree about which resource a request targets.
 * It removes path parameters (";x=y"), percent-decodes, turns backslashes into slashes, collapses duplicate
 * slashes and resolves "." / ".." segments. Anything malformed is rejected (empty result).
 */
public final class PathNormalizer {
    private PathNormalizer() {}

    /** Canonical path (always starts with "/"), or empty if the input is malformed or suspicious. */
    public static Optional<String> normalize(String rawPath) {
        if (rawPath == null || rawPath.isEmpty() || rawPath.charAt(0) != '/' || rawPath.length() > 2048) {
            return Optional.empty();
        }
        String path = rawPath;
        // Decode up to twice: "%252e%252e" must not hide a traversal from the authorisation check.
        for (int i = 0; i < 2; i++) {
            Optional<String> decoded = percentDecode(path);
            if (decoded.isEmpty()) {
                return Optional.empty();
            }
            path = decoded.get();
        }
        path = path.replace('\\', '/');
        for (int i = 0; i < path.length(); i++) {
            char c = path.charAt(i);
            if (c < 0x20 || c == 0x7f) {
                return Optional.empty(); // control characters (incl. NUL, CR, LF)
            }
        }
        Deque<String> stack = new ArrayDeque<>();
        for (String segment : path.split("/", -1)) {
            int semi = segment.indexOf(';');
            String seg = semi >= 0 ? segment.substring(0, semi) : segment; // drop path parameters
            if (seg.isEmpty() || seg.equals(".")) {
                continue;
            }
            if (seg.equals("..")) {
                if (!stack.isEmpty()) {
                    stack.removeLast();
                }
                continue;
            }
            stack.addLast(seg);
        }
        return Optional.of("/" + String.join("/", stack));
    }

    /** True if the canonical path equals the prefix or lies below it (case-insensitive on purpose). */
    public static boolean under(String canonicalPath, String prefix) {
        String p = canonicalPath.toLowerCase(Locale.ROOT);
        String f = prefix.toLowerCase(Locale.ROOT);
        return p.equals(f) || p.startsWith(f.endsWith("/") ? f : f + "/");
    }

    public static boolean underAny(String canonicalPath, List<String> prefixes) {
        return prefixes.stream().anyMatch(prefix -> under(canonicalPath, prefix));
    }

    /** Re-encodes a canonical path for forwarding (only unreserved characters and "/" stay literal). */
    public static String encode(String canonicalPath) {
        StringBuilder sb = new StringBuilder();
        for (byte b : canonicalPath.getBytes(StandardCharsets.UTF_8)) {
            int c = b & 0xff;
            boolean safe = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '.' || c == '_' || c == '~' || c == '/';
            if (safe) {
                sb.append((char) c);
            } else {
                sb.append('%').append(String.format("%02X", c));
            }
        }
        return sb.toString();
    }

    private static Optional<String> percentDecode(String s) {
        if (s.indexOf('%') < 0) {
            return Optional.of(s);
        }
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '%') {
                if (i + 2 >= s.length()) { // a '%' needs two hex digits after it
                    return Optional.empty();
                }
                int hi = Character.digit(s.charAt(i + 1), 16);
                int lo = Character.digit(s.charAt(i + 2), 16);
                if (hi < 0 || lo < 0) {
                    return Optional.empty();
                }
                out.write((hi << 4) | lo);
                i += 2;
            } else {
                byte[] bytes = String.valueOf(c).getBytes(StandardCharsets.UTF_8);
                out.write(bytes, 0, bytes.length);
            }
        }
        String decoded = out.toString(StandardCharsets.UTF_8);
        return decoded.indexOf('�') >= 0 ? Optional.empty() : Optional.of(decoded);
    }
}
