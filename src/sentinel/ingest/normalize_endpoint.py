"""Normalizer: WinPulse Windows endpoint logs from Kafka -> NormalizedEvent on events.normalized.

WinPulse carries real Windows Event Log fields (see windows/README.md), which is attacker-influenced
input on a compromised host (a process name, a command line, a script block are all written by
whoever is running on the box) -- every field is validated and bounded here; anything that cannot be
turned into a valid event is counted and dropped. Run as a service:
    python -m sentinel.ingest.normalize_endpoint
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from typing import Any

from pydantic import ValidationError

from sentinel.common.config import get_settings
from sentinel.common.logging import get_logger
from sentinel.common.schema import EventType, NormalizedEvent

log = get_logger(__name__)
ENDPOINT_TOPIC = "logs.endpoint"
EVENT_IDS: dict[int, EventType] = {
    4688: "process_create",
    7045: "service_install",
    4104: "powershell_script_block",
}


def _ts(value: Any) -> float:
    """Event time in epoch seconds; implausible or missing values fall back to 'now'."""
    try:
        t = float(value)
    except (TypeError, ValueError):
        return time.time()
    return t if 946_684_800 < t < 4_102_444_800 else time.time()  # between 2000 and 2100


def _str(value: Any) -> str | None:
    return None if value is None else str(value)


def _user(domain: Any, name: Any) -> str | None:
    """'CORP\\\\alice' style, or just the bare name if there is no domain."""
    name = _str(name)
    if not name:
        return None
    domain = _str(domain)
    return f"{domain}\\{name}" if domain else name


def normalize_winpulse(raw: dict[str, Any]) -> NormalizedEvent | None:
    """One WinPulse record -> an endpoint event. None for records that must not become events."""
    event_id = raw.get("event_id")
    event_type = EVENT_IDS.get(event_id) if isinstance(event_id, int) else None
    if event_type is None or not isinstance(raw.get("data"), dict):
        return None
    data = raw["data"]
    host = _str(raw.get("host"))
    ts = _ts(raw.get("ts"))

    if event_type == "process_create":
        return NormalizedEvent(
            source="endpoint",
            event_type=event_type,
            timestamp_generated=ts,
            src_ip=host,
            user=_user(data.get("SubjectDomainName"), data.get("SubjectUserName")),
            process_name=_str(data.get("NewProcessName")),
            parent_process=_str(data.get("ParentProcessName")),
            command_line=_str(data.get("CommandLine")),
        )
    if event_type == "service_install":
        return NormalizedEvent(
            source="endpoint",
            event_type=event_type,
            timestamp_generated=ts,
            src_ip=host,
            user=_str(data.get("AccountName")),
            process_name=_str(data.get("ServiceName")),
            command_line=_str(data.get("ImagePath")),
        )
    # powershell_script_block: the script text is "the code that ran", the role command_line
    # plays for process_create; process_name is always powershell.exe (4104 implies it).
    return NormalizedEvent(
        source="endpoint",
        event_type=event_type,
        timestamp_generated=ts,
        src_ip=host,
        user=_str(data.get("UserId")),
        process_name="powershell.exe",
        command_line=_str(data.get("ScriptBlockText")),
    )


def normalize_message(payload: bytes | str) -> NormalizedEvent | None:
    """Parse one Kafka message. Never raises on bad input."""
    try:
        raw = json.loads(payload)
        if not isinstance(raw, dict):
            return None
        return normalize_winpulse(raw)
    except (ValueError, ValidationError):  # JSONDecodeError and UnicodeDecodeError are ValueErrors
        return None


def main(argv: list[str] | None = None) -> int:
    from confluent_kafka import Consumer

    from sentinel.ingest.producer import EventProducer

    ap = argparse.ArgumentParser(
        description="Normalize WinPulse endpoint logs into events.normalized"
    )
    ap.add_argument("--group", default="sentinel-normalize-endpoint")
    ap.add_argument("--from-beginning", action="store_true")
    ap.add_argument("--idle-exit", type=float, default=0.0)
    a = ap.parse_args(argv)

    cfg = get_settings()
    out = EventProducer(cfg.kafka_bootstrap, cfg.events_topic)
    consumer = Consumer(
        {
            "bootstrap.servers": cfg.kafka_bootstrap,
            "group.id": a.group,
            "auto.offset.reset": "earliest" if a.from_beginning else "latest",
            "enable.auto.commit": True,
        }
    )
    consumer.subscribe([ENDPOINT_TOPIC])
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
            event = normalize_message(payload) if payload is not None else None
            if event is None:
                counts["dropped"] += 1
                continue
            out.send(event)
            counts["normalized"] += 1
    except KeyboardInterrupt:
        pass
    finally:
        consumer.close()
        out.flush()
    print(dict(counts), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
