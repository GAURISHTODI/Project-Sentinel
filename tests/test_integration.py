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


# ------------------------------------------------------------------ PostgreSQL repository


@pytest.fixture
def pg():  # type: ignore[no-untyped-def]
    import psycopg

    from sentinel.respond.repo import PgRepo

    dsn = get_settings().database_url.get_secret_value()
    try:
        repo = PgRepo(dsn)
    except psycopg.OperationalError:
        pytest.skip("Postgres from the compose core profile is not reachable")
    tag = uuid.uuid4().hex[:8]
    yield repo, tag, dsn
    with psycopg.connect(dsn, autocommit=True) as c:  # test incidents/locks are removable
        c.execute("DELETE FROM incidents WHERE event_id LIKE %s", (f"itest-{tag}%",))
        c.execute("DELETE FROM locked_accounts WHERE username LIKE %s", (f"itest-{tag}%",))
    repo.close()


def _det(tag: str, ip: str, ts: float) -> "object":
    from sentinel.common.schema import Detection

    return Detection(
        event_id=f"itest-{tag}-{ip}", rule_id="SEN-001", attack_id="T1110", severity="high",
        score=0.8, src_ip=ip, user=f"itest-{tag}", timestamp_event=ts, explanation="integration",
    )  # fmt: skip


def test_pg_incident_grouping_and_lock_roundtrip(pg) -> None:  # type: ignore[no-untyped-def]
    repo, tag, dsn = pg
    ip = f"203.0.113.{uuid.UUID(tag.ljust(32, '0')).int % 200 + 20}"
    d1, d2 = _det(tag, ip, 1_700_000_000.0), _det(tag, ip, 1_700_000_050.0)
    a, b = repo.create_incident(d1), repo.create_incident(d2)
    assert a.created and not b.created and a.incident_id == b.incident_id
    import psycopg

    with psycopg.connect(dsn) as c:
        count, status = c.execute(
            "SELECT event_count, status FROM incidents WHERE id = %s", (a.incident_id,)
        ).fetchone()
    assert (count, status) == (2, "open")
    repo.mark_responded(a.incident_id, 1_700_000_001.0)
    user = f"itest-{tag}"
    assert repo.lock_account(user, "test", 1_900_000_000.0) is True
    assert repo.lock_account(user, "test", 1_900_000_000.0) is False  # idempotent
    assert repo.unlock_account(user) is True and repo.unlock_account(user) is False


def test_pg_audit_chain_verifies_and_detects_tampering(pg) -> None:  # type: ignore[no-untyped-def]
    import psycopg

    repo, tag, dsn = pg
    for i in range(3):
        repo.audit("itest", "act", f"{tag}-{i}", {"i": i, "tag": tag, "nested": {"b": 1, "a": 2}})
    ok, n = repo.verify_chain()
    assert ok and n >= 3
    with psycopg.connect(dsn, autocommit=True) as c:
        row = c.execute(
            "SELECT id, target FROM audit_log WHERE actor = 'itest' AND target = %s", (f"{tag}-1",)
        ).fetchone()
        assert row is not None
        # The append-only trigger blocks this edit for everyone; the owner disables it only to
        # simulate a privileged tamperer, who the hash chain must still catch.
        c.execute("ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update")
        try:
            c.execute("UPDATE audit_log SET target = 'forged' WHERE id = %s", (row[0],))
            assert repo.verify_chain()[0] is False
        finally:
            c.execute("UPDATE audit_log SET target = %s WHERE id = %s", (row[1], row[0]))
            c.execute("ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_update")
    assert repo.verify_chain()[0] is True
