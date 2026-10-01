import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from sentinel.common.schema import MAX_LEN, Detection, NormalizedEvent
from sentinel.generator.core import Generator, parse_mix
from sentinel.generator.run import main
from sentinel.generator.scenarios import ATTACKS
from sentinel.ingest.producer import EventProducer


def _events(**kw: Any) -> list[NormalizedEvent]:
    return list(Generator(eps=200, duration=5, **kw).stream())


def test_exact_volume_and_ratio() -> None:
    evs = _events(attack_ratio=0.2)
    assert len(evs) == 1000
    attacks = sum(e.label != "benign" for e in evs)
    assert attacks == 200


def test_deterministic_for_seed() -> None:
    a = [e.model_dump(exclude={"event_id"}) for e in _events(seed=7)]
    b = [e.model_dump(exclude={"event_id"}) for e in _events(seed=7)]
    c = [e.model_dump(exclude={"event_id"}) for e in _events(seed=8)]
    assert a == b and a != c


def test_all_four_sources_present() -> None:
    assert {e.source for e in _events()} == {"app", "auth", "network", "endpoint"}


def test_timestamps_monotonic_and_paced() -> None:
    ts = [e.timestamp_generated for e in _events()]
    assert ts == sorted(ts)
    assert ts[-1] - ts[0] == pytest.approx(5 - 1 / 200, abs=0.01)


def test_every_scenario_can_be_generated() -> None:
    for name in ATTACKS:
        evs = list(Generator(100, 3, attack_ratio=0.5, mix={name: 1.0}).stream())
        assert {e.label for e in evs if e.label != "benign"} == {name}


def test_attackers_use_documentation_ranges_only() -> None:
    for e in _events(attack_ratio=0.3):
        if e.label != "benign":
            assert e.src_ip is not None
            assert e.src_ip.startswith(("203.0.113.", "198.51.100.", "10."))


def test_attack_payloads_present() -> None:
    evs = list(Generator(200, 5, attack_ratio=0.5, mix={"sqli": 1.0}).stream())
    paths = [e.path or "" for e in evs if e.label == "sqli"]
    assert paths and all(
        "%27" in p
        or "UNION" in p
        or "SLEEP" in p
        or "ORDER" in p
        or "DROP" in p
        or "--" in p
        or "1%3D1" in p
        for p in paths
    )


def test_benign_traffic_has_noise_but_no_attack_labels() -> None:
    evs = list(Generator(300, 5, attack_ratio=0.0).stream())
    assert {e.label for e in evs} == {"benign"}
    fails = sum(e.event_type == "login" and e.status == 401 for e in evs)
    assert fails > 0  # benign typos exist, so rules must tolerate them


def test_bad_args_rejected() -> None:
    with pytest.raises(ValueError):
        Generator(0, 1)
    with pytest.raises(ValueError):
        parse_mix("nope=1")
    assert parse_mix("sqli=3,dos") == {"sqli": 3.0, "dos": 1.0}


def test_untrusted_fields_are_truncated_not_rejected() -> None:
    ev = NormalizedEvent(
        source="app",
        event_type="http_request",
        path="A" * 100_000,
        user_agent="B" * 5000,
        user="C" * 999,
    )
    assert len(ev.path or "") == MAX_LEN["path"]
    assert len(ev.user_agent or "") == MAX_LEN["user_agent"]
    assert len(ev.user or "") == MAX_LEN["user"]


def test_schema_rejects_unknown_fields_and_bad_values() -> None:
    with pytest.raises(ValidationError):
        NormalizedEvent(source="app", event_type="http_request", surprise="x")  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        NormalizedEvent(source="app", event_type="http_request", dst_port=70000)
    with pytest.raises(ValidationError):
        NormalizedEvent(source="bogus", event_type="http_request")  # type: ignore[arg-type]


def test_strip_label_for_detectors() -> None:
    ev = NormalizedEvent(source="auth", event_type="login", label="brute_force")
    assert ev.strip_label().label is None and ev.label == "brute_force"


def test_detection_requires_exactly_one_detector() -> None:
    ok = Detection(event_id="e", rule_id="SEN-001", attack_id="T1110", score=0.9, explanation="x")
    assert ok.model_name is None
    with pytest.raises(ValidationError):
        Detection(event_id="e", score=0.5, explanation="neither")
    with pytest.raises(ValidationError):
        Detection(event_id="e", rule_id="SEN-001", model_name="rf", score=0.5, explanation="both")
    with pytest.raises(ValidationError):
        Detection(event_id="e", rule_id="SEN-001", score=1.5, explanation="out of range")


class FakeProducer:
    def __init__(self, fail_first: bool = False) -> None:
        self.messages: list[tuple[str, bytes, bytes | None]] = []
        self.fail_first, self.flushed = fail_first, False

    def produce(self, topic: str, value: bytes, key: bytes | None = None, **kw: Any) -> None:
        if self.fail_first:
            self.fail_first = False
            raise BufferError("queue full")
        self.messages.append((topic, value, key))

    def poll(self, timeout: float) -> int:
        return 0

    def flush(self, timeout: float = 0) -> int:
        self.flushed = True
        return 0


def test_producer_serializes_and_keys_by_ip() -> None:
    fake = FakeProducer()
    prod = EventProducer("unused", "events.normalized", producer=fake)
    ev = NormalizedEvent(source="auth", event_type="login", src_ip="203.0.113.9", user="u1")
    prod.send(ev)
    prod.flush()
    topic, value, key = fake.messages[0]
    assert topic == "events.normalized" and key == b"203.0.113.9" and fake.flushed
    assert NormalizedEvent.model_validate_json(value).user == "u1"


def test_producer_retries_when_queue_full() -> None:
    fake = FakeProducer(fail_first=True)
    prod = EventProducer("unused", "t", producer=fake)
    prod.send(NormalizedEvent(source="app", event_type="http_request"))
    assert len(fake.messages) == 1 and prod.sent == 1


def test_cli_writes_jsonl(tmp_path: Path) -> None:
    out = tmp_path / "ev.jsonl"
    rc = main(["--eps", "100", "--duration", "2", "--sink", "jsonl", "--out", str(out), "--fast"])
    assert rc == 0
    rows = [json.loads(line) for line in out.read_text().splitlines()]
    assert len(rows) == 200
    assert Counter(r["source"] for r in rows).keys() <= {"app", "auth", "network", "endpoint"}
