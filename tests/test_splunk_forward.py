import json
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
import pytest

from sentinel.common.schema import Detection
from sentinel.respond.splunk_forward import (
    HecClient,
    detection_event,
    forward_audit,
    forward_incidents,
    incident_row_to_event,
)


class Sink:
    """Records HEC posts instead of making them, like tests/test_respond.py's Sink."""

    def __init__(self, status: int = 200) -> None:
        self.calls: list[dict[str, Any]] = []
        self.status = status

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(json.loads(request.content))
        return httpx.Response(self.status)


def hec(sink: Sink) -> HecClient:
    client = HecClient("https://splunk.example.test/collector", "tok", True, source="sentinel")
    client._client = httpx.Client(
        timeout=5.0, transport=httpx.MockTransport(sink), headers=client._client.headers
    )
    return client


# ------------------------------------------------------------------ HecClient


def test_hec_send_wraps_event_and_counts_success() -> None:
    sink = Sink()
    client = hec(sink)
    ok = client.send("sentinel:detection", {"a": 1}, 1_700_000_000.0)
    assert ok is True
    assert client.sent == 1 and client.failed == 0
    [call] = sink.calls
    assert call == {
        "time": 1_700_000_000.0,
        "source": "sentinel",
        "sourcetype": "sentinel:detection",
        "index": "sentinel",
        "event": {"a": 1},
    }


def test_hec_send_failure_is_swallowed_and_counted() -> None:
    sink = Sink(status=500)
    client = hec(sink)
    ok = client.send("sentinel:detection", {"a": 1}, 1_700_000_000.0)
    assert ok is False
    assert client.failed == 1 and client.sent == 0


def test_hec_send_never_raises_on_transport_error() -> None:
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route")

    client = HecClient("https://splunk.example.test/collector", "tok", True, source="sentinel")
    client._client = httpx.Client(timeout=5.0, transport=httpx.MockTransport(boom))
    ok = client.send("sentinel:detection", {"a": 1}, 1_700_000_000.0)
    assert ok is False
    assert client.failed == 1


# ------------------------------------------------------------------ pure mappers


def test_detection_event_prefers_rule_id_and_drops_label() -> None:
    d = Detection(
        event_id="e1", rule_id="SEN-001", attack_id="T1110", severity="high", score=0.9,
        src_ip="203.0.113.5", user="alice", explanation="brute force",
    )  # fmt: skip
    event = detection_event(d)
    assert event == {
        "event_id": "e1",
        "detector": "SEN-001",
        "attack_id": "T1110",
        "severity": "high",
        "score": 0.9,
        "src_ip": "203.0.113.5",
        "user": "alice",
        "explanation": "brute force",
    }


def test_detection_event_falls_back_to_model_name() -> None:
    d = Detection(
        event_id="e2", model_name="network_ae", severity="medium", score=0.5, explanation="anomaly"
    )
    assert detection_event(d)["detector"] == "network_ae"


def test_incident_row_to_event_serializes_timestamps_and_ip() -> None:
    cols = ["id", "src_ip", "detected_at", "status"]
    row = (7, "203.0.113.9", datetime(2026, 1, 1, tzinfo=UTC), "open")
    event = incident_row_to_event(row, cols)
    assert event["id"] == 7
    assert event["src_ip"] == "203.0.113.9"
    assert event["detected_at"] == "2026-01-01T00:00:00+00:00"
    assert event["status"] == "open"


def test_incident_row_to_event_handles_null_ip_and_timestamp() -> None:
    cols = ["id", "src_ip", "detected_at"]
    row = (3, None, None)
    event = incident_row_to_event(row, cols)
    assert event["src_ip"] is None
    assert event["detected_at"] is None


# ------------------------------------------------------------------ integration (real Postgres)


@pytest.fixture
def pg_dsn() -> str:
    import psycopg

    from sentinel.common.config import get_settings

    dsn = get_settings().database_url.get_secret_value()
    try:
        with psycopg.connect(dsn, connect_timeout=1):
            pass
    except psycopg.OperationalError:
        pytest.skip("Postgres from the compose core profile is not reachable")
    return dsn


@pytest.mark.integration
def test_forward_incidents_sends_new_rows_and_advances_cursor(pg_dsn: str) -> None:
    import psycopg

    tag = uuid.uuid4().hex[:8]
    with psycopg.connect(pg_dsn, autocommit=True) as conn:
        conn.execute(
            "INSERT INTO incidents (event_id, rule_id, attack_id, severity, score, src_ip, "
            "username, explanation, detected_at) VALUES "
            "(%s, 'SEN-001', 'T1110', 'high', 0.8, '203.0.113.5', %s, 'itest', now())",
            (f"itest-{tag}", f"itest-{tag}"),
        )
        try:
            sink = Sink()
            client = hec(sink)
            since = forward_incidents(pg_dsn, client, 0)
            assert since > 0
            assert any(c["event"].get("event_id") == f"itest-{tag}" for c in sink.calls)
            assert forward_incidents(pg_dsn, client, since) == since  # no new rows, cursor stable
        finally:
            conn.execute("DELETE FROM incidents WHERE event_id = %s", (f"itest-{tag}",))


@pytest.mark.integration
def test_failed_hec_send_keeps_cursor_so_row_is_retried(pg_dsn: str) -> None:
    import psycopg

    tag = uuid.uuid4().hex[:8]
    with psycopg.connect(pg_dsn, autocommit=True) as conn:
        row = conn.execute("SELECT coalesce(max(id), 0) FROM audit_log").fetchone()
        baseline = int(row[0]) if row else 0
        conn.execute(
            "INSERT INTO audit_log (actor, action, target, detail) VALUES "
            "('itest', 'block_ip', %s, '{}'::jsonb)",
            (f"itest-{tag}",),
        )
        try:
            down = hec(Sink(status=503))
            cursor = forward_audit(pg_dsn, down, baseline)
            assert cursor == baseline and down.failed >= 1

            up = Sink()
            forward_audit(pg_dsn, hec(up), cursor)
            assert [c["event"]["target"] for c in up.calls] == [f"itest-{tag}"]
        finally:
            conn.execute("DELETE FROM audit_log WHERE target = %s", (f"itest-{tag}",))


@pytest.mark.integration
def test_forward_audit_sends_new_rows_with_detail_as_dict(pg_dsn: str) -> None:
    import psycopg

    tag = uuid.uuid4().hex[:8]
    with psycopg.connect(pg_dsn, autocommit=True) as conn:
        conn.execute(
            "INSERT INTO audit_log (actor, action, target, detail) VALUES "
            "('itest', 'block_ip', %s, %s)",
            (f"itest-{tag}", json.dumps({"outcome": "applied", "detector": "SEN-001"})),
        )
        try:
            sink = Sink()
            client = hec(sink)
            since = forward_audit(pg_dsn, client, 0)
            assert since > 0
            [event] = [c["event"] for c in sink.calls if c["event"].get("target") == f"itest-{tag}"]
            assert event["detail"] == {"outcome": "applied", "detector": "SEN-001"}
        finally:
            conn.execute("DELETE FROM audit_log WHERE target = %s", (f"itest-{tag}",))
