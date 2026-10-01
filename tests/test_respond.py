import json
from pathlib import Path

import fakeredis
import httpx
import pytest
import redis
import yaml
from pydantic import ValidationError

from sentinel.common.schema import Detection, NormalizedEvent
from sentinel.detect.engine import CIC_ATTACK_MAP, DetectionEngine, NetworkMLDetector, Pipeline
from sentinel.detect.rules.engine import RuleEngine
from sentinel.detect.rules.state import MemoryStore
from sentinel.generator.core import Generator
from sentinel.respond.actions import MAX_TTL, Actions, Outcome, valid_ip
from sentinel.respond.notify import Notifier
from sentinel.respond.policy import DEFAULT_POLICY, Policy, load_policy
from sentinel.respond.repo import MemoryRepo
from sentinel.respond.responder import Responder


def det(
    rule: str = "SEN-001",
    ip: str | None = "203.0.113.5",
    sev: str = "high",
    user: str | None = "alice",
    ts: float = 1_700_000_000.0,
    expl: str = "test",
) -> Detection:
    return Detection(
        event_id=f"e-{rule}-{ip}",
        rule_id=rule,
        attack_id="T1110",
        severity=sev,  # type: ignore[arg-type]
        score=0.8,
        src_ip=ip,
        user=user,
        timestamp_event=ts,
        explanation=expl,
    )


class Sink:
    """Records webhook calls instead of making them."""

    def __init__(self, status: int = 200) -> None:
        self.calls: list[dict[str, object]] = []
        self.status = status

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(json.loads(request.content))
        return httpx.Response(self.status)


class Env:
    def __init__(
        self, policy: Policy | None = None, sink: Sink | None = None, suppress: float = 0.0
    ) -> None:
        self.r = fakeredis.FakeRedis(decode_responses=True)
        self.repo = MemoryRepo()
        self.sink = sink or Sink()
        self.policy = policy or load_policy()
        notifier = Notifier(
            "https://hooks.example.test/x", transport=httpx.MockTransport(self.sink)
        )
        self.actions = Actions(self.r, self.repo, notifier, self.policy)
        self.clock_now = 1_700_000_000.0
        self.responder = Responder(
            self.policy,
            self.actions,
            self.repo,
            MemoryStore(),
            clock=lambda: self.clock_now,
            suppress_seconds=suppress,
        )


# ------------------------------------------------------------------ policy


def test_default_policy_loads_and_protects_loopback() -> None:
    p = load_policy()
    assert p.is_protected("127.0.0.1") and not p.is_protected("203.0.113.5")
    assert p.escalation.enabled and not p.dry_run


def test_policy_resolution_order() -> None:
    p = load_policy()
    rule_resp = [{"action": "block_ip", "ttl_seconds": 60}]
    d = det(sev="low")
    assert [s.action for s in p.actions_for(d, rule_resp)] == ["create_incident", "block_ip"]
    assert [s.action for s in p.actions_for(d, None)] == ["create_incident"]  # severity default
    p.overrides["SEN-001"] = [{"action": "notify"}]
    assert [s.action for s in p.actions_for(d, rule_resp)] == ["create_incident", "notify"]


def test_policy_rejects_bad_config() -> None:
    base = yaml.safe_load(DEFAULT_POLICY.read_text())
    with pytest.raises(ValidationError):
        Policy.model_validate({**base, "protected_cidrs": ["not-a-cidr"]})
    with pytest.raises(ValidationError):
        Policy.model_validate({**base, "overrides": {"SEN-001": [{"action": "format_disk"}]}})
    with pytest.raises(ValidationError):
        Policy.model_validate({**base, "surprise": 1})


# ------------------------------------------------------------------ actions


def test_block_ip_is_idempotent_and_does_not_extend_ttl() -> None:
    e = Env()
    first = e.actions.block_ip(det(), {"ttl_seconds": 600})
    ttl_before = e.r.ttl("sen:blocklist:203.0.113.5")
    again = e.actions.block_ip(det(), {"ttl_seconds": 99999})
    assert (first.outcome, again.outcome) == (Outcome.APPLIED, Outcome.ALREADY_ACTIVE)
    assert 0 < ttl_before <= 600 and e.r.ttl("sen:blocklist:203.0.113.5") <= ttl_before


def test_block_ttl_is_capped() -> None:
    e = Env()
    e.actions.block_ip(det(), {"ttl_seconds": 10**12})
    assert e.r.ttl("sen:blocklist:203.0.113.5") <= MAX_TTL
    e.actions.block_ip(det(ip="203.0.113.6"), {"ttl_seconds": "garbage"})
    assert e.r.ttl("sen:blocklist:203.0.113.6") > 0


def test_protected_and_low_severity_not_blocked() -> None:
    e = Env()
    assert e.actions.block_ip(det(ip="127.0.0.1"), {}).outcome == Outcome.PROTECTED
    assert e.actions.block_ip(det(sev="low"), {}).outcome == Outcome.BELOW_SEVERITY
    assert e.actions.block_ip(det(sev="low"), {"force": True}).outcome == Outcome.APPLIED
    assert e.actions.block_ip(det(ip="::1"), {}).outcome == Outcome.PROTECTED


@pytest.mark.parametrize(
    "hostile",
    [
        "203.0.113.5; FLUSHALL",
        "../../etc/passwd",
        "1.2.3.4\r\nSET x y",
        "",
        "999.1.1.1",
        "a" * 5000,
    ],
)
def test_hostile_ip_values_never_reach_redis(hostile: str) -> None:
    e = Env()
    for action in (e.actions.block_ip, e.actions.rate_limit):
        assert action(det(ip=hostile), {}).outcome == Outcome.NO_TARGET
    assert e.r.keys("*") == []
    assert valid_ip(" 203.0.113.5 ") == "203.0.113.5"


def test_rate_limit_and_lock_account_are_idempotent() -> None:
    e = Env()
    assert e.actions.rate_limit(det(), {"limit_per_minute": 10}).outcome == Outcome.APPLIED
    assert e.actions.rate_limit(det(), {}).outcome == Outcome.ALREADY_ACTIVE
    assert e.r.get("sen:ratelimit:203.0.113.5") == "10"
    assert e.actions.lock_account(det(), {}).outcome == Outcome.APPLIED
    assert e.actions.lock_account(det(), {}).outcome == Outcome.ALREADY_ACTIVE
    assert "alice" in e.repo.locked and e.r.exists("sen:locked:alice")
    assert e.actions.lock_account(det(user=None), {}).outcome == Outcome.NO_TARGET


def test_incidents_are_grouped_not_duplicated() -> None:
    e = Env()
    a = e.actions.create_incident(det(ts=1_700_000_000), {})
    b = e.actions.create_incident(det(ts=1_700_000_100), {})  # same detector + IP + hour
    c = e.actions.create_incident(det(ip="203.0.113.9"), {})
    assert (a.outcome, b.outcome, c.outcome) == (
        Outcome.APPLIED,
        Outcome.ALREADY_ACTIVE,
        Outcome.APPLIED,
    )
    assert a.detail["id"] == b.detail["id"] != c.detail["id"]
    assert next(iter(e.repo.incidents.values()))["event_count"] == 2


def test_dry_run_changes_nothing() -> None:
    p = load_policy()
    p.dry_run = True
    e = Env(policy=p)
    out = e.responder.handle(det(sev="critical"))
    assert {r.action for r in out} >= {"block_ip", "notify"}
    assert e.r.keys("*") == [] and e.sink.calls == []  # nothing enforced, nobody notified
    assert e.repo.locked == {}
    assert (
        len(e.repo.incidents) == 1
    )  # incidents are still recorded: that is how a policy is judged
    assert {r.outcome for r in out if r.action != "create_incident"} == {Outcome.DRY_RUN}


# ------------------------------------------------------------------ notifications


def test_notification_is_sanitised_and_bounded() -> None:
    e = Env()
    d = det(expl="boom\x00\x1b[31m" + "A" * 1800 + "\nINJECT <@everyone>", ip="203.0.113.5")
    assert e.actions.notify(d, {}).outcome == Outcome.APPLIED
    text = str(e.sink.calls[0]["text"])
    assert "\x00" not in text and "\x1b" not in text and "\n" not in text and len(text) < 600


def test_notification_cooldown_and_failure_handling() -> None:
    e = Env()
    assert e.actions.notify(det(), {}).outcome == Outcome.APPLIED
    assert e.actions.notify(det(), {}).outcome == Outcome.ALREADY_ACTIVE
    assert len(e.sink.calls) == 1
    bad = Env(sink=Sink(status=500))
    assert bad.actions.notify(det(), {}).outcome == Outcome.FAILED  # reported, never raised


def test_notifier_config_validation() -> None:
    with pytest.raises(ValueError, match="https"):
        Notifier("http://evil.example/hook")
    with pytest.raises(ValueError):
        Notifier("https://x.test", flavor="irc")
    assert Notifier(None).send(det()) is False  # unconfigured: log only


# ------------------------------------------------------------------ responder


def test_full_response_to_brute_force() -> None:
    e = Env()
    rule_resp = {
        "SEN-001": [
            {"action": "block_ip", "ttl_seconds": 3600},
            {"action": "lock_account"},
            {"action": "create_incident"},
            {"action": "notify"},
        ]
    }
    e.responder.rule_responses = rule_resp
    out = e.responder.handle(det())
    assert [(r.action, r.outcome) for r in out] == [
        ("block_ip", Outcome.APPLIED),
        ("lock_account", Outcome.APPLIED),
        ("create_incident", Outcome.APPLIED),
        ("notify", Outcome.APPLIED),
    ]
    assert e.r.exists("sen:blocklist:203.0.113.5") and e.r.exists("sen:locked:alice")
    assert next(iter(e.repo.incidents.values()))["responded_ts"] is not None
    ok, n = e.repo.verify_chain()
    assert ok and n == 4  # one audit row per APPLIED action


def test_repeat_detection_is_fully_idempotent() -> None:
    e = Env()
    e.responder.rule_responses = {"SEN-001": [{"action": "block_ip"}, {"action": "notify"}]}
    e.responder.handle(det())
    audit_rows = len(e.repo.audit_rows)
    for _ in range(20):
        out = e.responder.handle(det())
        assert all(r.outcome == Outcome.ALREADY_ACTIVE for r in out)
    assert len(e.repo.audit_rows) == audit_rows and len(e.repo.incidents) == 1
    assert e.responder.stats[("block_ip", "already_active")] == 20


def test_one_failing_action_does_not_stop_the_rest() -> None:
    e = Env()

    def boom(*_a: object, **_k: object) -> bool:
        raise redis.ConnectionError("redis down")

    e.r.set = boom  # type: ignore[method-assign,assignment]
    e.responder.rule_responses = {
        "SEN-001": [{"action": "block_ip"}, {"action": "create_incident"}]
    }
    out = e.responder.handle(det())
    assert [r.outcome for r in out] == [Outcome.FAILED, Outcome.APPLIED]
    assert any(row["action"] == "block_ip" for row in e.repo.audit_rows)  # failure is audited too


def test_escalation_blocks_a_source_tripping_three_detectors() -> None:
    e = Env()
    e.responder.rule_responses = {}  # low-severity rules: incident only
    for i, rule in enumerate(["SEN-005", "SEN-003", "SEN-009"]):
        out = e.responder.handle(det(rule=rule, sev="low", ts=1_700_000_000 + i))
    assert [r.action for r in out][-1] == "block_ip" and out[-1].outcome == Outcome.APPLIED
    assert e.r.exists("sen:blocklist:203.0.113.5")
    # only two detectors from another source: no escalation
    for rule in ("SEN-005", "SEN-003"):
        e.responder.handle(det(rule=rule, ip="203.0.113.77", sev="low"))
    assert not e.r.exists("sen:blocklist:203.0.113.77")


def test_analyst_override_is_audited_and_reversible() -> None:
    e = Env()
    e.responder.rule_responses = {"SEN-001": [{"action": "block_ip"}, {"action": "lock_account"}]}
    e.responder.handle(det())
    assert e.actions.unblock_ip("203.0.113.5", actor="analyst1") is True
    assert e.actions.unlock_account("alice", actor="analyst1") is True
    assert not e.r.exists("sen:blocklist:203.0.113.5") and "alice" not in e.repo.locked
    assert [r["actor"] for r in e.repo.audit_rows][-2:] == ["analyst1", "analyst1"]
    with pytest.raises(ValueError):
        e.actions.unblock_ip("not-an-ip", actor="analyst1")


def test_audit_chain_detects_tampering() -> None:
    e = Env()
    for i in range(5):
        e.repo.audit("a", "act", f"t{i}", {"i": i})
    assert e.repo.verify_chain() == (True, 5)
    e.repo.audit_rows[2]["target"] = "forged"
    assert e.repo.verify_chain() == (False, 2)
    e2 = Env()
    for i in range(5):
        e2.repo.audit("a", "act", f"t{i}", {"i": i})
    del e2.repo.audit_rows[1]  # deleting a row also breaks the chain
    assert e2.repo.verify_chain()[0] is False


# ------------------------------------------------------------------ pipeline


class SpyDetector:
    def __init__(self) -> None:
        self.labels: list[str | None] = []

    def evaluate(self, ev: NormalizedEvent) -> list[Detection]:
        self.labels.append(ev.label)
        return []


def test_pipeline_drops_invalid_messages_and_strips_labels() -> None:
    spy = SpyDetector()
    pipe = Pipeline(DetectionEngine(RuleEngine(MemoryStore()), [spy]))
    good = NormalizedEvent(source="app", event_type="http_request", label="sqli").model_dump_json()
    for junk in (
        b"not json",
        b"{}",
        b'{"source": "app"}',
        b"\xff\xfe",
        b'{"source":"x","event_type":"y"}',
    ):
        assert pipe.handle_message(junk) == []
    pipe.handle_message(good)
    assert pipe.counts["invalid"] == 5 and pipe.counts["events"] == 1
    assert spy.labels == [None]  # the detector never saw the label


class FakePredictor:
    model_name = "network-xgb_binary"

    def __init__(self, attack: bool, label: str = "PortScan") -> None:
        self.attack, self.label = attack, label

    def is_attack(self, flow: dict[str, float]) -> tuple[bool, float]:
        if len(flow) < 3:
            raise ValueError("too few features")
        return self.attack, 0.97 if self.attack else 0.01

    def attack_type(self, flow: dict[str, float]) -> tuple[str, float]:
        return self.label, 0.9


def test_ml_detector_scores_cic_flows_and_skips_synthetic_ones() -> None:
    cic = NormalizedEvent(
        source="network",
        event_type="flow",
        src_ip="203.0.113.8",
        flow_features={"a": 1.0, "b": 2.0, "c": 3.0},
    )
    synthetic = NormalizedEvent(
        source="network", event_type="flow", flow_features={"duration": 1.0}
    )
    http = NormalizedEvent(source="app", event_type="http_request")
    ml = NetworkMLDetector(FakePredictor(True), FakePredictor(True, "DDoS"))  # type: ignore[arg-type]
    (d,) = ml.evaluate(cic)
    assert d.model_name == "network-xgb_binary" and d.rule_id is None
    assert d.attack_id == CIC_ATTACK_MAP["DDoS"] == "T1499" and d.severity == "high"
    assert "DDoS" in d.explanation
    assert ml.evaluate(synthetic) == [] and ml.evaluate(http) == []
    assert NetworkMLDetector(FakePredictor(False)).evaluate(cic) == []  # type: ignore[arg-type]


def test_end_to_end_attackers_blocked_and_no_benign_ip_is_ever_blocked() -> None:
    e = Env()
    rules = RuleEngine(MemoryStore())
    e.responder.rule_responses = {r.id: r.response for r in rules.rules}
    pipe = Pipeline(DetectionEngine(rules), e.responder)
    gen = Generator(eps=500, duration=30, attack_ratio=0.2, seed=3)
    attackers: set[str] = set()
    for ev in gen.stream():
        if ev.label != "benign" and ev.src_ip:
            attackers.add(ev.src_ip)
        pipe.handle_message(ev.model_dump_json())
    blocked = {k.removeprefix("sen:blocklist:") for k in e.r.scan_iter("sen:blocklist:*")}
    assert blocked and blocked <= attackers, f"non-attacker blocked: {blocked - attackers}"
    assert not any(ip.startswith("10.") for ip in blocked)
    assert e.repo.verify_chain()[0] and e.repo.incidents
    assert pipe.counts["detections"] > len(e.repo.incidents)  # grouping collapsed repeats


def test_policy_file_is_packaged() -> None:
    assert Path(DEFAULT_POLICY).exists()


# ------------------------------------------------------------------ repeat suppression


def test_repeats_are_counted_in_memory_then_flushed_in_one_batch() -> None:
    e = Env(suppress=30.0)
    e.responder.rule_responses = {"SEN-001": [{"action": "block_ip"}, {"action": "notify"}]}
    first = e.responder.handle(det())
    assert first and first[0].outcome == Outcome.APPLIED
    for _ in range(50):
        assert e.responder.handle(det()) == []  # no actions, no Redis/Postgres round trips
    row = next(iter(e.repo.incidents.values()))
    assert row["event_count"] == 1 and e.responder.stats[("suppressed", "repeat")] == 50
    e.responder.flush()
    assert row["event_count"] == 51  # all repeats reach the incident in a single update


def test_suppression_expires_and_actions_run_again() -> None:
    e = Env(suppress=30.0)
    e.responder.rule_responses = {"SEN-001": [{"action": "block_ip"}]}
    e.responder.handle(det())
    e.r.delete("sen:blocklist:203.0.113.5")  # block expired or was lifted by an analyst
    assert e.responder.handle(det()) == []  # still inside the suppression window
    e.clock_now += 31
    out = e.responder.handle(det())
    assert {r.action: r.outcome for r in out}["block_ip"] == Outcome.APPLIED  # re-applied
    assert next(iter(e.repo.incidents.values()))["event_count"] == 3  # 3 detections in all


def test_suppression_is_per_incident_and_does_not_hide_other_attackers() -> None:
    e = Env(suppress=30.0)
    e.responder.rule_responses = {"SEN-001": [{"action": "block_ip"}]}
    e.responder.handle(det(ip="203.0.113.5"))
    out = e.responder.handle(det(ip="203.0.113.6"))  # different source: must be handled
    assert out and out[0].outcome == Outcome.APPLIED
    assert e.r.exists("sen:blocklist:203.0.113.6")


def test_escalation_still_counts_distinct_detectors_under_suppression() -> None:
    e = Env(suppress=30.0)
    e.responder.rule_responses = {}
    for i, rule in enumerate(["SEN-005", "SEN-005", "SEN-003", "SEN-003", "SEN-009"]):
        e.responder.handle(det(rule=rule, sev="low", ts=1_700_000_000 + i))
    assert e.r.exists("sen:blocklist:203.0.113.5")


# ------------------------------------------------------------------ cached (partition-local) state


def test_cached_store_matches_memory_store_and_mirrors_to_redis() -> None:
    from sentinel.detect.rules.state import CachedStore, RedisStore

    r = fakeredis.FakeRedis(decode_responses=True)
    cached = CachedStore(RedisStore(r, prefix="t"), flush_interval=3600)
    mem = MemoryStore()
    for t in range(40):
        assert cached.record("k", t, f"m{t % 7}", 10) == mem.record("k", t, f"m{t % 7}", 10)
    assert cached.claim("c", 5, 60) and not cached.claim("c", 6, 60)
    assert r.zcard("t:win:k") == 0  # nothing written yet: batched
    cached.flush()
    assert r.zcard("t:win:k") == len(mem._win["k"]) and r.exists("t:fired:c")


def test_cached_store_flush_survives_redis_outage() -> None:
    from sentinel.detect.rules.state import CachedStore, RedisStore

    class Down(RedisStore):
        def apply(self, ops: list[tuple[str, str, float, str, int]]) -> None:
            raise redis.ConnectionError("down")

    cached = CachedStore(Down(fakeredis.FakeRedis()), flush_interval=0)
    assert cached.record("k", 1, "m", 10) == 1  # detection keeps working
    assert cached.record("k", 2, "n", 10) == 2 and cached.flush_errors >= 1


def test_rules_give_same_detections_on_cached_and_memory_store() -> None:
    from sentinel.detect.rules.state import CachedStore, RedisStore

    events = list(Generator(eps=300, duration=20, attack_ratio=0.2, seed=9).stream())
    a = RuleEngine(MemoryStore())
    b = RuleEngine(CachedStore(RedisStore(fakeredis.FakeRedis(decode_responses=True))))
    for ev in events:
        x = sorted((d.rule_id or "", d.event_id) for d in a.evaluate(ev.strip_label()))
        y = sorted((d.rule_id or "", d.event_id) for d in b.evaluate(ev.strip_label()))
        assert x == y
