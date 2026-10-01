"""Integration tests against the real compose stack; skipped when it is not running."""

import json
import os
import time
import uuid

import pytest
import redis

from sentinel.common.config import get_settings
from sentinel.common.schema import NormalizedEvent
from sentinel.detect.rules.engine import RuleEngine
from sentinel.detect.rules.state import MemoryStore, RedisStore
from sentinel.generator.core import Generator

pytestmark = pytest.mark.integration


@pytest.fixture
def real_redis() -> redis.Redis:  # type: ignore[type-arg]
    url = os.environ.get("REDIS_URL") or get_settings().redis_url.get_secret_value()
    client = redis.Redis.from_url(url, decode_responses=True, socket_connect_timeout=1)
    try:
        client.ping()
    except redis.RedisError:
        pytest.skip("Redis from the compose core profile is not reachable")
    return client


def test_rules_give_identical_detections_on_real_redis_and_memory(
    real_redis: redis.Redis,  # type: ignore[type-arg]
) -> None:
    prefix = f"test-{uuid.uuid4().hex[:8]}"  # isolate this run's keys
    events = list(Generator(eps=300, duration=20, attack_ratio=0.2, seed=5).stream())
    mem = RuleEngine(MemoryStore())
    red = RuleEngine(RedisStore(real_redis, prefix=prefix))
    try:
        for ev in events:
            a = sorted((d.rule_id or "", d.event_id) for d in mem.evaluate(ev.strip_label()))
            b = sorted((d.rule_id or "", d.event_id) for d in red.evaluate(ev.strip_label()))
            assert a == b
    finally:
        for key in real_redis.scan_iter(f"{prefix}:*"):
            real_redis.delete(key)


def test_kafka_roundtrip_preserves_events() -> None:
    from confluent_kafka import Consumer

    from sentinel.ingest.producer import EventProducer

    cfg = get_settings()
    topic = f"test.{uuid.uuid4().hex[:8]}"
    consumer = Consumer(
        {
            "bootstrap.servers": cfg.kafka_bootstrap,
            "group.id": topic,
            "auto.offset.reset": "earliest",
            "socket.timeout.ms": 3000,
        }
    )
    try:
        consumer.list_topics(timeout=3)
    except Exception:  # noqa: BLE001  # confluent raises a broad KafkaException when no broker
        consumer.close()
        pytest.skip("Kafka from the compose core profile is not reachable")
    sent = [
        NormalizedEvent(source="auth", event_type="login", src_ip="203.0.113.9", user=f"u{i}")
        for i in range(25)
    ]
    prod = EventProducer(cfg.kafka_bootstrap, topic)
    for ev in sent:
        prod.send(ev)
    prod.flush()
    consumer.subscribe([topic])
    got: list[NormalizedEvent] = []
    deadline = time.time() + 20
    while len(got) < len(sent) and time.time() < deadline:
        msg = consumer.poll(1.0)
        if msg is not None and msg.error() is None:
            got.append(NormalizedEvent.model_validate(json.loads(msg.value())))
    consumer.close()
    assert [g.event_id for g in got] == [s.event_id for s in sent]
