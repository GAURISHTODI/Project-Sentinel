import json
import time

import pytest

from sentinel.common.schema import MAX_LEN
from sentinel.detect.engine import DetectionEngine, Pipeline
from sentinel.detect.rules.engine import RuleEngine
from sentinel.detect.rules.state import MemoryStore
from sentinel.ingest.normalize import (
    ACCESS_TOPIC,
    AUTH_TOPIC,
    normalize_access,
    normalize_auth,
    normalize_message,
)

NOW = time.time()


def access(**kw: object) -> dict[str, object]:
    base: dict[str, object] = {
        "ts": NOW,
        "clientIp": "203.0.113.7",
        "method": "GET",
        "uri": "/search?q=shoes",
        "status": 200,
        "userAgent": "Mozilla/5.0",
        "user": None,
        "bytes": 10,
        "durationMs": 3,
    }
    base.update(kw)
    return base


def test_access_record_becomes_app_event() -> None:
    ev = normalize_access(access())
    assert ev is not None and ev.source == "app" and ev.event_type == "http_request"
    assert ev.src_ip == "203.0.113.7" and ev.path == "/search?q=shoes" and ev.status == 200
    assert ev.timestamp_generated == pytest.approx(NOW) and ev.label is None


def test_login_access_records_are_dropped_because_auth_records_cover_them() -> None:
    assert normalize_access(access(uri="/api/login", method="POST")) is None


def test_auth_record_becomes_login_event() -> None:
    ok = normalize_auth(
        {
            "ts": NOW,
            "clientIp": "198.51.100.4",
            "username": "alice",
            "outcome": "success",
            "userAgent": "ua",
        }
    )
    bad = normalize_auth(
        {"ts": NOW, "clientIp": "198.51.100.4", "username": "alice", "outcome": "failure"}
    )
    assert ok is not None and bad is not None
    assert (ok.source, ok.event_type, ok.status, ok.user) == ("auth", "login", 200, "alice")
    assert bad.status == 401


@pytest.mark.parametrize(
    "raw",
    [
        access(clientIp="not-an-ip"),
        access(clientIp=None),
        access(clientIp="1.2.3.4; DROP"),
        access(uri=None),
        {"clientIp": "203.0.113.7", "outcome": "maybe"},
        {"outcome": "success"},
    ],
)
def test_unusable_records_are_dropped(raw: dict[str, object]) -> None:
    assert normalize_access(raw) is None and normalize_auth(raw) is None


def test_hostile_values_are_bounded_and_sanitised() -> None:
    ev = normalize_access(
        access(
            uri="/x?" + "A" * 100_000,
            userAgent="B" * 5000,
            method="GET" * 100,
            status=99999,
            ts="garbage",
        )
    )
    assert ev is not None
    assert (
        len(ev.path or "") == MAX_LEN["path"] and len(ev.user_agent or "") == MAX_LEN["user_agent"]
    )
    assert ev.status is None  # out-of-range status is not trusted
    assert ev.timestamp_generated == pytest.approx(time.time(), abs=5)  # bad timestamp -> now
    old = normalize_access(access(ts=5))
    assert old is not None and old.timestamp_generated > 1_000_000_000


@pytest.mark.parametrize(
    "payload", [b"not json", b"[]", b"123", b"null", b"\xff\xfe", b'{"clientIp": 5}', b""]
)
def test_normalize_message_never_raises(payload: bytes) -> None:
    assert normalize_message(ACCESS_TOPIC, payload) is None
    assert normalize_message(AUTH_TOPIC, payload) is None
    assert normalize_message("some.other.topic", json.dumps(access())) is None


def test_label_field_cannot_be_smuggled_in_from_a_log() -> None:
    ev = normalize_access(access(label="benign", campaign="c1"))
    assert ev is not None and ev.label is None and ev.campaign is None


def test_real_attack_logs_trigger_the_expected_rules() -> None:
    """Raw logs shaped like the target's output flow through normalizer -> rules."""
    pipe = Pipeline(DetectionEngine(RuleEngine(MemoryStore())))
    attacks = {
        "SEN-002": access(
            uri="/api/search?q=%27%20UNION%20SELECT%20id%2C%20username%2C0%2Cpassword%20FROM%20users%20--"
        ),
        "SEN-003": access(uri="/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"),
        "SEN-009": access(uri="/api/files?name=..%2f..%2fsecret.txt"),
        "SEN-005": access(uri="/", userAgent="sqlmap/1.7.2#stable (https://sqlmap.org)"),
    }
    for expected, raw in attacks.items():
        ev = normalize_message(ACCESS_TOPIC, json.dumps(raw))
        assert ev is not None
        fired = {d.rule_id for d in pipe.handle_message(ev.model_dump_json())}
        assert expected in fired, f"{expected} did not fire; got {fired}"


def test_failed_logins_with_injection_username_and_bruteforce() -> None:
    pipe = Pipeline(DetectionEngine(RuleEngine(MemoryStore())))
    inj = normalize_message(
        AUTH_TOPIC,
        json.dumps(
            {"ts": NOW, "clientIp": "203.0.113.9", "username": "admin'--", "outcome": "success"}
        ),
    )
    assert inj is not None
    assert "SEN-002" in {d.rule_id for d in pipe.handle_message(inj.model_dump_json())}
    fired: set[str | None] = set()
    for i in range(12):
        ev = normalize_message(
            AUTH_TOPIC,
            json.dumps(
                {
                    "ts": NOW + i,
                    "clientIp": "203.0.113.10",
                    "username": "alice",
                    "outcome": "failure",
                }
            ),
        )
        assert ev is not None
        fired |= {d.rule_id for d in pipe.handle_message(ev.model_dump_json())}
    assert "SEN-001" in fired
