package com.sentinel.responder.store;

import com.sentinel.responder.GatewayProperties;
import jakarta.annotation.PreDestroy;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;
import redis.clients.jedis.Pipeline;
import redis.clients.jedis.Response;

/**
 * Reads Sentinel's keys ({@code sen:blocklist:<ip>}, {@code sen:ratelimit:<ip>}) and counts requests in a
 * fixed one-minute window, all in ONE pipelined round trip so the gateway adds about 1 ms per request.
 */
@Component
@ConditionalOnProperty(name = "gateway.store", havingValue = "redis", matchIfMissing = true)
public class RedisGatewayStore implements GatewayStore {
    private final JedisPool pool;

    public RedisGatewayStore(GatewayProperties props) {
        var r = props.redis();
        JedisPoolConfig cfg = new JedisPoolConfig();
        cfg.setMaxTotal(16);
        cfg.setMaxIdle(8);
        cfg.setTestOnBorrow(false);
        String password = r.password().isBlank() ? null : r.password();
        this.pool = new JedisPool(cfg, r.host(), r.port(), r.timeoutMs(), password);
    }

    @Override
    public Decision check(String ip, int defaultLimit, long minuteEpoch) {
        String counter = "gw:rl:" + ip + ":" + minuteEpoch;
        try (Jedis jedis = pool.getResource()) {
            Pipeline p = jedis.pipelined();
            Response<Boolean> blocked = p.exists("sen:blocklist:" + ip);
            Response<String> dynamic = p.get("sen:ratelimit:" + ip);
            Response<Long> count = p.incr(counter);
            p.expire(counter, 120);
            p.sync();
            int limit = defaultLimit;
            String dyn = dynamic.get();
            if (dyn != null) {
                try {
                    limit = Math.max(1, Math.min(defaultLimit, Integer.parseInt(dyn.trim())));
                } catch (NumberFormatException ignored) {
                    // a malformed value must never loosen or break the limit: keep the default
                }
            }
            return new Decision(Boolean.TRUE.equals(blocked.get()), limit, count.get());
        }
    }

    @PreDestroy
    void close() {
        pool.close();
    }
}
