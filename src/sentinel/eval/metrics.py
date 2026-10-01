"""Pure metric computation for a labeled run. No I/O, no randomness: easy to test.

Ground truth is the generator's `label` (scenario) and `campaign` id. Detection is judged at two
levels, because stateful rules (thresholds, windows) fire on the event that crosses the threshold,
not on every event of an attack:

* campaign level - was this attack campaign detected at all, and by the rule meant to catch it?
* event level    - how many benign events raised an alert (false positives)?
"""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from sentinel.common.schema import Detection, NormalizedEvent

ENFORCEMENT = {"block_ip", "rate_limit", "lock_account"}

# scenario label -> rules that are meant to catch it (rules not yet built are filtered out)
EXPECTED_RULES: dict[str, set[str]] = {
    "brute_force": {"SEN-001"},
    "credential_stuffing": {"SEN-008"},
    "sqli": {"SEN-002"},
    "xss": {"SEN-003"},
    "path_traversal": {"SEN-009"},
    "scanner": {"SEN-005"},
    "port_scan": {"SEN-004"},
    "dos": {"SEN-007"},
    "valid_account_abuse": {"SEN-006"},
    "endpoint_spawn": {"SEN-010"},
    "endpoint_powershell": {"SEN-011"},
    "endpoint_service": {"SEN-012"},
}
# A successful stuffing login from a new country is also genuine valid-account abuse.
ALSO_TRUE_FOR: dict[str, set[str]] = {"SEN-006": {"credential_stuffing"}}
STATELESS = {"sqli", "xss", "path_traversal", "scanner"}  # one alert per malicious event


@dataclass
class Response:
    event_id: str
    action: str
    outcome: str
    ts: float


@dataclass
class RunData:
    events: list[NormalizedEvent]  # with ground-truth labels
    detections: list[Detection]
    responses: list[Response] = field(default_factory=list)
    wall_seconds: float = 0.0
    realtime: bool = False  # latency figures are only meaningful when events were paced live
    service_counts: dict[str, int] = field(default_factory=dict)  # what the service says it did


def _pct(values: list[float], q: float) -> float:
    s = sorted(values)
    return s[min(len(s) - 1, int(q * len(s)))]


def _lat(values: list[float]) -> dict[str, float | int] | None:
    if not values:
        return None
    ms = [v * 1000 for v in values]
    return {
        "n": len(ms),
        "mean_ms": round(statistics.fmean(ms), 1),
        "p50_ms": round(_pct(ms, 0.5), 1),
        "p95_ms": round(_pct(ms, 0.95), 1),
        "max_ms": round(max(ms), 1),
    }


def compute(run: RunData, rule_ids: set[str]) -> dict[str, Any]:
    by_event: dict[str, list[Detection]] = defaultdict(list)
    for d in run.detections:
        by_event[d.event_id].append(d)
    label_of = {e.event_id: e.label or "unlabeled" for e in run.events}

    # ---- campaigns
    camp: dict[str, dict[str, Any]] = {}
    for e in run.events:
        if e.campaign is None:
            continue
        c = camp.setdefault(
            e.campaign, {"label": e.label, "first": e.timestamp_generated, "ids": []}
        )
        c["first"] = min(c["first"], e.timestamp_generated)
        c["ids"].append(e.event_id)
    resp_by_event: dict[str, list[Response]] = defaultdict(list)
    for r in run.responses:
        resp_by_event[r.event_id].append(r)

    ttd: list[float] = []
    ttr: list[float] = []
    per: dict[str, dict[str, Any]] = {}
    campaign_rules: dict[str, set[str]] = {}
    for cid, c in camp.items():
        label = str(c["label"])
        expected = EXPECTED_RULES.get(label, set()) & rule_ids
        dets = [d for i in c["ids"] for d in by_event.get(i, [])]
        fired = {str(d.rule_id or d.model_name) for d in dets}
        campaign_rules[cid] = fired
        row = per.setdefault(
            label,
            {
                "campaigns": 0,
                "events": 0,
                "detected_any": 0,
                "detected_expected": 0,
                "covered": bool(expected),
            },
        )
        row["campaigns"] += 1
        row["events"] += len(c["ids"])
        row["detected_any"] += bool(dets)
        row["detected_expected"] += bool(fired & expected)
        if dets:
            ttd.append(min(d.timestamp_detected for d in dets) - c["first"])
        enf = [
            r.ts
            for i in c["ids"]
            for r in resp_by_event.get(i, [])
            if r.action in ENFORCEMENT and r.outcome == "applied"
        ]
        if enf:
            ttr.append(min(enf) - c["first"])
    for label, row in per.items():
        row["recall_expected_rule"] = round(row["detected_expected"] / row["campaigns"], 4)
        if label in STATELESS:
            expected = EXPECTED_RULES[label] & rule_ids
            ev_ids = [e.event_id for e in run.events if e.label == label]
            hit = sum(any(str(d.rule_id) in expected for d in by_event.get(i, [])) for i in ev_ids)
            row["event_recall"] = round(hit / max(len(ev_ids), 1), 4)

    covered = {k: v for k, v in per.items() if v["covered"]}
    tot_c = sum(v["campaigns"] for v in covered.values())
    overall = {
        "covered_scenarios": sorted(covered),
        "uncovered_scenarios": sorted(k for k, v in per.items() if not v["covered"]),
        "campaigns_covered": tot_c,
        "campaign_recall_expected_rule": round(
            sum(v["detected_expected"] for v in covered.values()) / max(tot_c, 1), 4
        ),
    }

    # ---- per rule (detection-level precision, campaign-level recall)
    scen_of_rule: dict[str, set[str]] = defaultdict(set)
    for label, label_rules in EXPECTED_RULES.items():
        for rule in label_rules:
            scen_of_rule[rule].add(label)
    for rule, extra in ALSO_TRUE_FOR.items():
        scen_of_rule[rule] |= extra
    per_rule: dict[str, Any] = {}
    for rid in sorted(rule_ids):
        mine = [d for d in run.detections if d.rule_id == rid]
        tp = sum(label_of.get(d.event_id) in scen_of_rule[rid] for d in mine)
        own = [
            c
            for c in camp.values()
            if c["label"] in EXPECTED_RULES and rid in EXPECTED_RULES[str(c["label"])]
        ]
        own_hit = sum(rid in campaign_rules[cid] for cid, c in camp.items() if c in own)
        per_rule[rid] = {
            "detections": len(mine),
            "true_positive_detections": tp,
            "false_positive_detections": len(mine) - tp,
            "precision": round(tp / len(mine), 4) if mine else None,
            "campaigns": len(own),
            "campaigns_detected": own_hit,
            "campaign_recall": round(own_hit / len(own), 4) if own else None,
        }

    # ---- false positives on benign traffic
    benign = [e for e in run.events if e.label == "benign"]
    fp_events = [e for e in benign if e.event_id in by_event]
    fp_by_rule = Counter(
        str(d.rule_id or d.model_name) for e in fp_events for d in by_event[e.event_id]
    )
    false_pos = {
        "benign_events": len(benign),
        "benign_events_alerted": len(fp_events),
        "false_positive_rate_event": round(len(fp_events) / max(len(benign), 1), 6),
        "by_rule": dict(fp_by_rule),
    }

    # ---- campaign-level confusion matrix (benign row is event-level)
    cols = sorted(rule_ids) + ["none"]
    matrix: dict[str, dict[str, int]] = {}
    for cid, c in camp.items():
        label = str(c["label"])
        expected = EXPECTED_RULES.get(label, set()) & rule_ids
        fired = campaign_rules[cid]
        primary = next(iter(sorted(fired & expected)), None) or next(iter(sorted(fired)), "none")
        matrix.setdefault(label, dict.fromkeys(cols, 0))[
            primary if primary in cols else "none"
        ] += 1
    brow = dict.fromkeys(cols, 0)
    for e in benign:
        first = by_event.get(e.event_id)
        brow[str(first[0].rule_id) if first and first[0].rule_id in cols else "none"] += 1
    matrix["benign (events)"] = brow

    n = len(run.events)
    return {
        "events": n,
        "attack_events": n - len(benign),
        "campaigns": len(camp),
        "detections": len(run.detections),
        "scenarios": per,
        "overall": overall,
        "per_rule": per_rule,
        "false_positives": false_pos,
        "confusion_matrix": {
            "note": "rows: true scenario; cols: rule that detected the campaign "
            "(attacks, campaign level) or alerted on the event (benign row)",
            "columns": cols,
            "rows": matrix,
        },
        "latency": {
            # attack start -> first alert: includes the time a threshold rule needs to accumulate
            "time_to_detect": _lat(ttd) if run.realtime else None,
            # triggering event -> detection: the pipeline's own speed, per detection
            "pipeline_per_detection": _lat(
                [
                    d.timestamp_detected - d.timestamp_event
                    for d in run.detections
                    if d.timestamp_event is not None
                ]
            )
            if run.realtime
            else None,
            "time_to_respond": _lat(ttr) if run.realtime else None,
            "note": None if run.realtime else "not measured: events were not paced in real time",
        },
        "throughput": {
            "events": n,
            "seconds": round(run.wall_seconds, 2),
            "events_per_second": round(n / run.wall_seconds, 1) if run.wall_seconds else None,
            "service_events_processed": run.service_counts.get("events"),
            "service_invalid_dropped": run.service_counts.get("invalid", 0),
        },
    }
