package com.sentinel.shop.events;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sentinel.shop.ShopProperties;
import jakarta.annotation.PreDestroy;
import java.util.Properties;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.apache.kafka.clients.producer.KafkaProducer;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.clients.producer.ProducerRecord;
import org.apache.kafka.common.serialization.StringSerializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

/**
 * Publishes events to Kafka from a single background thread with a bounded queue, so a slow or
 * unavailable broker can never slow down or fail a user request (events are dropped and counted).
 */
@Component
@ConditionalOnProperty(prefix = "shop.kafka", name = "enabled", havingValue = "true")
public class KafkaEventSink implements EventSink {
    private static final Logger log = LoggerFactory.getLogger(KafkaEventSink.class);

    private final ShopProperties.Kafka cfg;
    private final ObjectMapper mapper = new ObjectMapper();
    private final KafkaProducer<String, String> producer;
    private final ThreadPoolExecutor executor = new ThreadPoolExecutor(
            1, 1, 0L, TimeUnit.MILLISECONDS, new ArrayBlockingQueue<>(10_000),
            r -> {
                Thread t = new Thread(r, "kafka-event-sink");
                t.setDaemon(true);
                return t;
            },
            new ThreadPoolExecutor.DiscardPolicy());
    private final AtomicLong dropped = new AtomicLong();

    public KafkaEventSink(ShopProperties props) {
        this.cfg = props.kafka();
        Properties p = new Properties();
        p.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, cfg.bootstrap());
        p.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        p.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class.getName());
        p.put(ProducerConfig.LINGER_MS_CONFIG, 20);
        p.put(ProducerConfig.MAX_BLOCK_MS_CONFIG, 2000);
        p.put(ProducerConfig.DELIVERY_TIMEOUT_MS_CONFIG, 10_000);
        p.put(ProducerConfig.REQUEST_TIMEOUT_MS_CONFIG, 5_000);
        this.producer = new KafkaProducer<>(p);
    }

    @Override
    public void access(AccessEvent event) {
        send(cfg.accessTopic(), event.clientIp(), event);
    }

    @Override
    public void auth(AuthEvent event) {
        send(cfg.authTopic(), event.clientIp(), event);
    }

    private void send(String topic, String key, Object event) {
        if (executor.getQueue().remainingCapacity() == 0) {
            if (dropped.incrementAndGet() % 1000 == 1) {
                log.warn("event queue full, dropping events (total dropped {})", dropped.get());
            }
            return;
        }
        executor.execute(() -> {
            try {
                String json = mapper.writeValueAsString(event);
                producer.send(new ProducerRecord<>(topic, key, json), (meta, err) -> {
                    if (err != null) {
                        log.warn("kafka send failed: {}", err.toString());
                    }
                });
            } catch (JsonProcessingException e) {
                log.warn("event serialisation failed: {}", e.toString());
            }
        });
    }

    @PreDestroy
    void close() {
        executor.shutdown();
        producer.close(java.time.Duration.ofSeconds(3));
    }
}
