package com.sentinel.shop.events;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.stereotype.Component;

/** Fallback when Kafka is disabled (unit tests, local runs): keeps the events in memory. */
@Component
@ConditionalOnMissingBean(KafkaEventSink.class)
public class LocalEventSink implements EventSink {
    private final List<AccessEvent> accessEvents = new CopyOnWriteArrayList<>();
    private final List<AuthEvent> authEvents = new CopyOnWriteArrayList<>();

    @Override
    public void access(AccessEvent event) {
        if (accessEvents.size() < 1000) {
            accessEvents.add(event);
        }
    }

    @Override
    public void auth(AuthEvent event) {
        if (authEvents.size() < 1000) {
            authEvents.add(event);
        }
    }

    public List<AccessEvent> accessEvents() {
        return accessEvents;
    }

    public List<AuthEvent> authEvents() {
        return authEvents;
    }
}
