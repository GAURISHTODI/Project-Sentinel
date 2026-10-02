import json
from pathlib import Path

import pytest

import sentinel.eval.evaluate as evaluate_module
from sentinel.common.schema import Detection, NormalizedEvent
from sentinel.eval.evaluate import _parse_counts, collect_sections, main, run_inproc
from sentinel.eval.metrics import Response, RunData, compute

RULES = {"SEN-001", "SEN-002", "SEN-005"}


def ev(
    i: str, label: str, campaign: str | None, ts: float, ip: str = "203.0.113.5"
) -> NormalizedEvent:
    return NormalizedEvent(event_id=i, source="app", event_type="http_request", src_ip=ip,
                           label=label, campaign=campaign, timestamp_generated=ts)  # fmt: skip


def det(event_id: str, rule: str, ts_event: float, ts_det: float) -> Detection:
    return Detection(
        event_id=event_id,
        rule_id=rule,
        attack_id="T1190",
        score=0.7,
        timestamp_event=ts_event,
        timestamp_detected=ts_det,
        explanation="x",
    )


def small_run(realtime: bool = True) -> RunData:
    events = [
        ev("b1", "benign", None, 0.0, "10.0.0.1"), ev("b2", "benign", None, 0.1, "10.0.0.2"),
        ev("b3", "benign", None, 0.2, "10.0.0.3"), ev("b4", "benign", None, 0.3, "10.0.0.4"),
        ev("s1", "sqli", "c1", 1.0), ev("s2", "sqli", "c1", 1.1),       # campaign 1: caught
        ev("s3", "sqli", "c2", 5.0),                                      # campaign 2: missed
        ev("u1", "scanner", "c3", 8.0), ev("u2", "scanner", "c3", 8.1),  # caught by wrong rule only
        ev("x1", "endpoint_powershell", "c4", 9.0),                      # no rule exists for it yet
    ]  # fmt: skip
    dets = [
        det("s1", "SEN-002", 1.0, 1.2), det("s2", "SEN-002", 1.1, 1.4),
        det("u1", "SEN-002", 8.0, 8.5),  # scanner campaign flagged by SQLi rule, not SEN-005
        det("b2", "SEN-001", 0.1, 0.3),  # false positive on a benign event
    ]  # fmt: skip
    resp = [Response("s1", "block_ip", "applied", 1.5), Response("s1", "notify", "applied", 1.1),
            Response("s2", "block_ip", "already_active", 1.6)]  # fmt: skip
    return RunData(events, dets, resp, wall_seconds=2.0, realtime=realtime)


def test_campaign_recall_by_expected_rule() -> None:
    m = compute(small_run(), RULES)
    sc = m["scenarios"]
    assert sc["sqli"]["campaigns"] == 2 and sc["sqli"]["detected_expected"] == 1
    assert sc["sqli"]["recall_expected_rule"] == 0.5
    assert sc["scanner"]["detected_any"] == 1 and sc["scanner"]["detected_expected"] == 0
    assert m["overall"]["campaigns_covered"] == 3  # sqli x2 + scanner x1
    assert m["overall"]["campaign_recall_expected_rule"] == pytest.approx(1 / 3, abs=1e-4)


def test_uncovered_scenarios_are_reported_not_hidden() -> None:
    m = compute(small_run(), RULES)
    assert m["scenarios"]["endpoint_powershell"]["covered"] is False
    assert "endpoint_powershell" in m["overall"]["uncovered_scenarios"]
    assert "endpoint_powershell" not in m["overall"]["covered_scenarios"]


def test_false_positives_on_benign_events() -> None:
    fp = compute(small_run(), RULES)["false_positives"]
    assert fp["benign_events"] == 4 and fp["benign_events_alerted"] == 1
    assert fp["false_positive_rate_event"] == 0.25 and fp["by_rule"] == {"SEN-001": 1}


def test_per_rule_precision_and_recall() -> None:
    pr = compute(small_run(), RULES)["per_rule"]
    assert pr["SEN-002"]["detections"] == 3 and pr["SEN-002"]["true_positive_detections"] == 2
    assert pr["SEN-002"]["precision"] == pytest.approx(2 / 3, abs=1e-4)
    assert pr["SEN-002"]["campaign_recall"] == 0.5
    assert pr["SEN-001"]["precision"] == 0.0 and pr["SEN-005"]["detections"] == 0
    assert pr["SEN-005"]["precision"] is None  # no detections: undefined, not 0 or 1


def test_latency_definitions() -> None:
    lat = compute(small_run(), RULES)["latency"]
    # campaigns detected: c1 (first event 1.0, first detection ts 1.2) and c3 (8.0 -> 8.5)
    assert lat["time_to_detect"]["n"] == 2 and lat["time_to_detect"]["mean_ms"] == pytest.approx(
        350
    )
    # response: c1 first enforcement at 1.5 (notify is not enforcement, already_active is ignored)
    assert lat["time_to_respond"]["n"] == 1 and lat["time_to_respond"]["mean_ms"] == pytest.approx(
        500
    )
    # pipeline: per detection (0.2, 0.3, 0.5, 0.2)
    assert lat["pipeline_per_detection"]["n"] == 4
    assert lat["pipeline_per_detection"]["mean_ms"] == pytest.approx(300)


def test_latency_withheld_when_not_realtime() -> None:
    lat = compute(small_run(realtime=False), RULES)["latency"]
    assert lat["time_to_detect"] is None and lat["pipeline_per_detection"] is None and lat["note"]


def test_confusion_matrix_rows_and_columns() -> None:
    cm = compute(small_run(), RULES)["confusion_matrix"]
    assert cm["columns"] == ["SEN-001", "SEN-002", "SEN-005", "none"]
    assert cm["rows"]["sqli"] == {"SEN-001": 0, "SEN-002": 1, "SEN-005": 0, "none": 1}
    assert cm["rows"]["scanner"]["SEN-002"] == 1  # caught, but by the wrong rule
    assert (
        cm["rows"]["benign (events)"]["SEN-001"] == 1 and cm["rows"]["benign (events)"]["none"] == 3
    )
    assert sum(cm["rows"]["endpoint_powershell"].values()) == 1


def test_throughput_and_counts() -> None:
    run = small_run()
    run.service_counts = {"events": 10, "invalid": 2}
    t = compute(run, RULES)["throughput"]
    assert t["events"] == 10 and t["events_per_second"] == 5.0
    assert t["service_events_processed"] == 10 and t["service_invalid_dropped"] == 2


def test_parse_counts_from_service_stderr() -> None:
    tail = "noise\n{'events': 60000, 'detections': 12, 'invalid': 3}\n"
    assert _parse_counts(tail) == {"events": 60000, "detections": 12, "invalid": 3}
    assert _parse_counts("nothing useful") == {}
    assert _parse_counts("{'events': oops}") == {}


def test_inproc_run_and_metrics_json(tmp_path: Path) -> None:
    out = tmp_path / "metrics.json"
    assert main(["--mode", "inproc", "--eps", "200", "--duration", "10", "--out", str(out)]) == 0
    m = json.loads(out.read_text())
    assert m["config"]["mode"] == "inproc" and m["config"]["seed"] == 42
    assert m["pipeline"]["events"] == 2000 and m["rules"]["count"] >= 9
    assert m["pipeline"]["latency"]["time_to_detect"] is None  # never invented
    assert m["rules"]["technique_count"] == len(m["rules"]["attack_techniques"])


def test_collect_sections_nests_ml_by_model_name_but_owasp_is_the_whole_section(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression test: an earlier version unwrapped any single-file directory, which silently
    collapsed ml/network.json's own keys up a level (breaking dig(m, "ml", "network", ...))."""
    monkeypatch.setattr(evaluate_module, "RESULTS", tmp_path)
    (tmp_path / "ml").mkdir()
    (tmp_path / "ml" / "network.json").write_text(json.dumps({"rf_binary": {"f1": 0.99}}))
    (tmp_path / "owasp").mkdir()
    (tmp_path / "owasp" / "summary.json").write_text(json.dumps({"v1_open": 14, "v2_open": 0}))

    out = collect_sections()

    assert out["ml"]["network"]["rf_binary"]["f1"] == 0.99  # nested under the model's own name
    assert out["owasp"] == {"v1_open": 14, "v2_open": 0}  # the file *is* the section, not nested


def test_collect_sections_is_empty_when_no_results_directories_exist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(evaluate_module, "RESULTS", tmp_path / "does-not-exist")
    assert collect_sections() == {}


def test_run_is_deterministic_for_a_seed() -> None:
    a, b = run_inproc(200, 10, 7, 0.1), run_inproc(200, 10, 7, 0.1)
    assert sorted(d.rule_id or "" for d in a.detections) == sorted(
        d.rule_id or "" for d in b.detections
    )
