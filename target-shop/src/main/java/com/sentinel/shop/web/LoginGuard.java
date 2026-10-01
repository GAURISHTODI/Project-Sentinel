package com.sentinel.shop.web;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * v2 brute-force protection: at most 10 login attempts per minute per client IP, and the account
 * is locked for 15 minutes after 5 consecutive failures. v1 does not call this class at all.
 */
@Component
public class LoginGuard {
    static final int MAX_PER_MINUTE = 10;
    static final int LOCK_AFTER_FAILURES = 5;
    static final Duration LOCK_TIME = Duration.ofMinutes(15);

    private final Map<String, Deque<Instant>> attempts = new ConcurrentHashMap<>();
    private final Map<String, Integer> failures = new ConcurrentHashMap<>();
    private final Map<String, Instant> lockedUntil = new ConcurrentHashMap<>();

    public enum Verdict { OK, RATE_LIMITED, LOCKED }

    public Verdict check(String ip, String username) {
        Instant now = Instant.now();
        Instant lock = lockedUntil.get(username);
        if (lock != null) {
            if (lock.isAfter(now)) {
                return Verdict.LOCKED;
            }
            lockedUntil.remove(username);
            failures.remove(username);
        }
        Deque<Instant> q = attempts.computeIfAbsent(ip, k -> new ArrayDeque<>());
        synchronized (q) {
            Instant cutoff = now.minusSeconds(60);
            while (!q.isEmpty() && q.peekFirst().isBefore(cutoff)) {
                q.pollFirst();
            }
            if (q.size() >= MAX_PER_MINUTE) {
                return Verdict.RATE_LIMITED;
            }
            q.addLast(now);
        }
        return Verdict.OK;
    }

    public void failure(String username) {
        int n = failures.merge(username, 1, Integer::sum);
        if (n >= LOCK_AFTER_FAILURES) {
            lockedUntil.put(username, Instant.now().plus(LOCK_TIME));
        }
    }

    /** Clears all counters (used by tests and by an operator after an incident). */
    public void reset() {
        attempts.clear();
        failures.clear();
        lockedUntil.clear();
    }

    public void success(String username) {
        failures.remove(username);
    }
}
