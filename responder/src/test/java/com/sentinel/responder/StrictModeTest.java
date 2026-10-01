package com.sentinel.responder;

import static com.sentinel.responder.TestSupport.get;
import static org.assertj.core.api.Assertions.assertThat;

import com.sentinel.responder.TestSupport.FakeUpstream;
import com.sentinel.responder.TestSupport.MemoryStore;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/** failOpen=false: if Sentinel's decision store is down the gateway refuses to serve (strict mode). */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
    "gateway.store=memory", "gateway.jwt-secret=" + TestSupport.SECRET, "gateway.fail-open=false"})
@Import(TestSupport.StoreConfig.class)
class StrictModeTest {
    static FakeUpstream upstream;
    @LocalServerPort int port;
    @Autowired MemoryStore store;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) throws Exception {
        upstream = new FakeUpstream();
        r.add("gateway.upstream", () -> "http://127.0.0.1:" + upstream.port());
    }

    @Test
    void storeOutageGives503AndNothingReachesTheUpstream() throws Exception {
        store.failing = true;
        assertThat(get(port, "/api/products").statusCode()).isEqualTo(503);
        assertThat(upstream.requests).isEmpty();
        assertThat(get(port, "/_gw/health").statusCode()).isEqualTo(200); // health stays reachable
        store.failing = false;
        assertThat(get(port, "/api/products").statusCode()).isEqualTo(200);
    }
}
