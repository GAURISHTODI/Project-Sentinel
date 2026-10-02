"""Kafka producer for normalized events. Keyed by src_ip so one source stays on one partition."""

from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel

from sentinel.common.logging import get_logger
from sentinel.common.schema import NormalizedEvent

log = get_logger(__name__)


class RawProducer(Protocol):
    def produce(self, topic: str, value: bytes, key: bytes | None = ...) -> None: ...
    def poll(self, timeout: float) -> int: ...
    def flush(self, timeout: float = ...) -> int: ...


class EventProducer:
    def __init__(self, bootstrap: str, topic: str, producer: RawProducer | None = None) -> None:
        self.topic = topic
        self._p: RawProducer
        if producer is None:
            from confluent_kafka import Producer

            self._p = Producer(
                {"bootstrap.servers": bootstrap, "linger.ms": 5, "compression.type": "lz4"}
            )
        else:
            self._p = producer
        self.sent = 0

    def send(self, ev: NormalizedEvent) -> None:
        key = (ev.src_ip or ev.event_id).encode()
        value = ev.model_dump_json().encode()
        try:
            self._p.produce(self.topic, value, key)
        except BufferError:  # local queue full: serve delivery callbacks, then retry once
            self._p.poll(0.5)
            self._p.produce(self.topic, value, key)
        self.sent += 1
        self._p.poll(0)

    def send_model(self, model: BaseModel, key: str) -> None:
        """Publish any pydantic model (e.g. a Detection) as JSON with an explicit partition key."""
        self.send_raw(model.model_dump_json(), key)

    def send_raw(self, payload: str, key: str) -> None:
        """Publish an already-serialized JSON string (e.g. a raw WinPulse record) with a key."""
        value = payload.encode()
        try:
            self._p.produce(self.topic, value, key.encode())
        except BufferError:
            self._p.poll(0.5)
            self._p.produce(self.topic, value, key.encode())
        self.sent += 1
        self._p.poll(0)

    def poll(self) -> None:
        """Serve delivery callbacks without blocking (keeps the local queue draining)."""
        self._p.poll(0)

    def flush(self) -> None:
        self._p.flush(10)
        log.info("flushed", extra={"fields": {"sent": self.sent, "topic": self.topic}})
