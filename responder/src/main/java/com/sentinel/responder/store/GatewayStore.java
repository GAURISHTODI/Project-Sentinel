package com.sentinel.responder.store;

/** Per-request lookup of what Sentinel has decided about a client address. One round trip. */
public interface GatewayStore {

    /**
     * @param blocked  Sentinel has the address on its blocklist
     * @param limit    allowed requests this minute (Sentinel's dynamic limit, else the default)
     * @param count    requests seen from this address in the current minute, including this one
     */
    record Decision(boolean blocked, int limit, long count) {}

    Decision check(String ip, int defaultLimit, long minuteEpoch);
}
