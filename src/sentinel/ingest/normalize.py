"""Normalizers: raw application logs from Kafka -> NormalizedEvent on events.normalized.

Input comes straight from a (possibly compromised or attacked) application, so every field is
validated and bounded; anything that cannot be turned into a valid event is counted and dropped.
Run as a service: python -m sentinel.ingest.normalize
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
import time
from collections import Counter
from typing import Any

from pydantic import ValidationError

from sentinel.common.config import get_settings
from sentinel.common.logging import get_logger
from sentinel.common.schema import NormalizedEvent

log = get_logger(__name__)
ACCESS_TOPIC = "logs.app"
AUTH_TOPIC = "logs.auth"
LOGIN_PATH = "/api/login"


def _ip(value: Any) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def _ts(value: Any) -> float:
    """Event time in epoch seconds; implausible or missing values fall back to 'now'."""
    try:
        t = float(value)
    except (TypeError, ValueError):
        return time.time()
    return t if 946_684_800 < t < 4_102_444_800 else time.time()  # between 2000 and 2100


def _str(value: Any) -> str | None:
    return None if value is None else str(value)


def _status(value: Any) -> int | None:
    try:
        s = int(value)
    except (TypeError, ValueError):
        return None
    return s if 0 <= s <= 999 else None


def normalize_access(raw: dict[str, Any]) -> NormalizedEvent | None:
    """HTTP access record -> app event. Returns None for records that must not become events."""
    uri = _str(raw.get("uri"))
    ip = _ip(raw.get("clientIp"))
    if uri is None or ip is None:
        return None
    if uri.split("?", 1)[0] == LOGIN_PATH:
        return None  # the matching auth record already represents this login attempt
    return NormalizedEvent(
        source="app",
        event_type="http_request",
        timestamp_generated=_ts(raw.get("ts")),
        src_ip=ip,
        method=(_str(raw.get("method")) or "")[:16] or None,
        path=uri,
        status=_status(raw.get("status")),
        user_agent=_str(raw.get("userAgent")),
        user=_str(raw.get("user")),
    )


def normalize_auth(raw: dict[str, Any]) -> NormalizedEvent | None:
    """Authentication attempt -> auth login event (success = 200, failure = 401)."""
    ip = _ip(raw.get("clientIp"))
    outcome = _str(raw.get("outcome"))
    if ip is None or outcome not in {"success", "failure"}:
        return None
    return NormalizedEvent(
        source="auth",
        event_type="login",
        timestamp_generated=_ts(raw.get("ts")),
        src_ip=ip,
        user=_str(raw.get("username")),
        method="POST",
        path=LOGIN_PATH,
        status=200 if outcome == "success" else 401,
        user_agent=_str(raw.get("userAgent")),
    )


def normalize_message(topic: str, payload: bytes | str) -> NormalizedEvent | None:
    """Parse one Kafka message. Never raises on bad input."""
    try:
        raw = json.loads(payload)
        if not isinstance(raw, dict):
            return None
        if topic == ACCESS_TOPIC:
            return normalize_access(raw)
        if topic == AUTH_TOPIC:
            return normalize_auth(raw)
    except (ValueError, ValidationError):  # JSONDecodeError and UnicodeDecodeError are ValueErrors
        return None
    return None


def ensure_topics(bootstrap: str, names: list[str]) -> None:
    """Create the input topics if missing, so a consumer never waits on a topic that is absent."""
    from confluent_kafka.admin import AdminClient
    from confluent_kafka.cimpl import NewTopic

    admin = AdminClient({"bootstrap.servers": bootstrap})
    for name, fut in admin.create_topics([NewTopic(t, 1, 1) for t in names]).items():
        try:
            fut.result(timeout=15)
        except Exception as exc:  # noqa: BLE001  # TOPIC_ALREADY_EXISTS is the normal case
            if "TOPIC_ALREADY_EXISTS" not in str(exc):
                log.error(
                    "could not create topic", extra={"fields": {"topic": name, "error": str(exc)}}
                )


def main(argv: list[str] | None = None) -> int:
    from confluent_kafka import Consumer

    from sentinel.ingest.producer import EventProducer

    ap = argparse.ArgumentParser(description="Normalize app/auth logs into events.normalized")
    ap.add_argument("--group", default="sentinel-normalize")
    ap.add_argument(
        "--latest", action="store_true", help="skip logs written before start (default: no loss)"
    )
    ap.add_argument("--idle-exit", type=float, default=0.0)
    a = ap.parse_args(argv)

    cfg = get_settings()
    ensure_topics(cfg.kafka_bootstrap, [ACCESS_TOPIC, AUTH_TOPIC])
    out = EventProducer(cfg.kafka_bootstrap, cfg.events_topic)
    consumer = Consumer(
        {
            "bootstrap.servers": cfg.kafka_bootstrap,
            "group.id": a.group,
            "auto.offset.reset": "latest"
            if a.latest
            else "earliest",  # a log pipeline must not lose logs
            "enable.auto.commit": True,
            "topic.metadata.refresh.interval.ms": 5000,  # notice topics created after start-up
        }
    )
    consumer.subscribe([ACCESS_TOPIC, AUTH_TOPIC])
    counts: Counter[str] = Counter()
    last = time.time()
    try:
        while True:
            msg = consumer.poll(0.5)
            if msg is None or msg.error():
                if a.idle_exit and counts and time.time() - last > a.idle_exit:
                    break
                continue
            last = time.time()
            payload = msg.value()
            topic = msg.topic() or ""
            event = normalize_message(topic, payload) if payload is not None else None
            if event is None:
                counts["dropped"] += 1
                continue
            out.send(event)
            counts[topic] += 1
    except KeyboardInterrupt:
        pass
    finally:
        consumer.close()
        out.flush()
    print(dict(counts), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
