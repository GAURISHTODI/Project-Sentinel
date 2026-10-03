"""Forwards detections (Kafka) and incidents (PostgreSQL) to Splunk via HEC.

Splunk is visibility only: it never drives a decision, so a Splunk outage must never affect
detection or response. Every HEC call is best-effort (logged and counted on failure, never raised)
and runs on its own schedule independent of the detection pipeline.

Run as a service:  python -m sentinel.respond.splunk_forward [--idle-exit N] [--from-beginning]
"""

from __future__ import annotations

import argparse
import sys
import time
from collections import Counter
from datetime import datetime
from typing import Any

import httpx
import psycopg

from sentinel.common.config import get_settings
from sentinel.common.logging import get_logger
from sentinel.common.schema import Detection

log = get_logger(__name__)
INCIDENT_POLL_SECONDS = 10.0


class HecClient:
    """A thin, best-effort wrapper over Splunk's HTTP Event Collector."""

    def __init__(self, url: str, token: str, verify_tls: bool, source: str) -> None:
        self.url, self.source = url, source
        self._client = httpx.Client(
            timeout=5.0,
            verify=verify_tls,
            headers={"Authorization": f"Splunk {token}"},
        )
        self.sent = 0
        self.failed = 0

    def send(self, sourcetype: str, event: dict[str, Any], event_time: float) -> bool:
        payload = {
            "time": event_time,
            "source": self.source,
            "sourcetype": sourcetype,
            "index": "sentinel",
            "event": event,
        }
        try:
            resp = self._client.post(self.url, json=payload)
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            self.failed += 1
            log.warning("HEC send failed", extra={"fields": {"error": str(exc)[:200]}})
            return False
        self.sent += 1
        return True

    def close(self) -> None:
        self._client.close()


def detection_event(d: Detection) -> dict[str, Any]:
    return {
        "event_id": d.event_id,
        "detector": d.rule_id or d.model_name,
        "attack_id": d.attack_id,
        "severity": d.severity,
        "score": d.score,
        "src_ip": d.src_ip,
        "user": d.user,
        "explanation": d.explanation,
    }


def incident_row_to_event(row: tuple[Any, ...], columns: list[str]) -> dict[str, Any]:
    data = dict(zip(columns, row, strict=True))
    for key in ("detected_at", "created_at", "last_seen"):
        if isinstance(data.get(key), datetime):
            data[key] = data[key].isoformat()
    if data.get("src_ip") is not None:
        data["src_ip"] = str(data["src_ip"])
    return data


def forward_incidents(dsn: str, hec: HecClient, since_id: int) -> int:
    """Forward incidents with id > since_id. Stops at the first HEC failure so it is retried."""
    cols = [
        "id", "event_id", "rule_id", "model_name", "attack_id", "severity", "score",
        "src_ip", "username", "status", "event_count", "explanation", "detected_at",
        "last_seen", "responded_ts",
    ]  # fmt: skip
    with psycopg.connect(dsn) as conn:
        rows = conn.execute(
            f"SELECT {', '.join(cols)} FROM incidents WHERE id > %s ORDER BY id",  # noqa: S608
            (since_id,),
        ).fetchall()
        for row in rows:
            event = incident_row_to_event(row, cols)
            ts = event.get("detected_at")
            event_time = datetime.fromisoformat(ts).timestamp() if ts else time.time()
            if not hec.send("sentinel:incident", event, event_time):
                break  # retry from this row on the next poll
            since_id = max(since_id, int(event["id"]))
    return since_id


def forward_audit(dsn: str, hec: HecClient, since_id: int) -> int:
    """Forward audit_log rows with id > since_id. This is the authoritative record of every
    enforcement action actually taken (block_ip, lock_account, unblock_ip, ...), which is what the
    "blocked IPs" saved search needs -- the incidents table itself does not record that."""
    cols = ["id", "ts", "actor", "action", "target", "detail"]
    with psycopg.connect(dsn) as conn:
        rows = conn.execute(
            f"SELECT {', '.join(cols)} FROM audit_log WHERE id > %s ORDER BY id",  # noqa: S608
            (since_id,),
        ).fetchall()
        for row in rows:
            event = dict(zip(cols, row, strict=True))
            ts = event.pop("ts")
            event["detail"] = dict(event["detail"]) if event["detail"] else {}
            sent = hec.send(
                "sentinel:audit", event, ts.timestamp() if isinstance(ts, datetime) else time.time()
            )
            if not sent:
                break  # retry from this row on the next poll
            since_id = max(since_id, int(event["id"]))
    return since_id


def main(argv: list[str] | None = None) -> int:
    from confluent_kafka import Consumer

    ap = argparse.ArgumentParser(description="Forward Sentinel detections/incidents to Splunk HEC")
    ap.add_argument("--group", default="sentinel-splunk-forward")
    ap.add_argument("--from-beginning", action="store_true")
    ap.add_argument("--idle-exit", type=float, default=0.0)
    a = ap.parse_args(argv)

    cfg = get_settings()
    hec = HecClient(
        cfg.splunk_hec_url,
        cfg.splunk_hec_token.get_secret_value(),
        cfg.splunk_verify_tls,
        source="sentinel",
    )
    consumer = Consumer(
        {
            "bootstrap.servers": cfg.kafka_bootstrap,
            "group.id": a.group,
            "auto.offset.reset": "earliest" if a.from_beginning else "latest",
            "enable.auto.commit": True,
        }
    )
    consumer.subscribe([cfg.detections_topic])
    counts: Counter[str] = Counter()
    last_msg = time.time()
    last_incident_poll = 0.0
    since_incident_id = 0
    since_audit_id = 0
    try:
        while True:
            msg = consumer.poll(0.5)
            now = time.time()
            if now - last_incident_poll > INCIDENT_POLL_SECONDS:
                dsn = cfg.database_url.get_secret_value()
                try:
                    since_incident_id = forward_incidents(dsn, hec, since_incident_id)
                    since_audit_id = forward_audit(dsn, hec, since_audit_id)
                except psycopg.Error as exc:
                    log.warning(
                        "incident/audit poll failed", extra={"fields": {"error": str(exc)[:200]}}
                    )
                last_incident_poll = now
            if msg is None or msg.error():
                if a.idle_exit and counts["detections"] and now - last_msg > a.idle_exit:
                    break
                continue
            last_msg = now
            payload = msg.value()
            if payload is None:
                continue
            try:
                d = Detection.model_validate_json(payload)
            except ValueError:
                counts["invalid"] += 1
                continue
            counts["detections"] += 1
            ts = d.timestamp_event or d.timestamp_detected
            if hec.send("sentinel:detection", detection_event(d), ts):
                counts["hec_sent"] += 1
            else:
                counts["hec_failed"] += 1
    except KeyboardInterrupt:
        pass
    finally:
        consumer.close()
        hec.close()
    print(dict(counts), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
