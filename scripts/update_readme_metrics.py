"""Fill the README Results table from results/metrics.json (hard rule 1: no hand-typed numbers).

    python scripts/update_readme_metrics.py [--check]

Anything missing from metrics.json is written as TBD. With --check the README is not modified; the
exit code is 1 if it is out of date (useful in CI).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

START, END = "<!-- METRICS:START -->", "<!-- METRICS:END -->"
TBD = "TBD"


def dig(d: Any, *path: str) -> Any:
    for key in path:
        if not isinstance(d, dict) or key not in d:
            return None
        d = d[key]
    return d


def lat(block: dict[str, Any] | None) -> str:
    if not block:
        return TBD
    return f"mean {block['mean_ms']:.0f} ms, p95 {block['p95_ms']:.0f} ms (n={block['n']})"


def rows(m: dict[str, Any]) -> list[tuple[str, str]]:
    p = m.get("pipeline", {})
    cfg = m.get("config", {})
    out: list[tuple[str, str]] = []
    if cfg:
        out.append(
            (
                "Evaluation run",
                f"{cfg['mode']} mode, {p.get('events', 0):,} labeled events, "
                f"{cfg['eps']:,} events/s target, seed {cfg['seed']}, "
                f"commit `{m.get('git_commit')}`",
            )
        )
    thr = dig(p, "throughput") or {}
    if thr.get("events_per_second") is not None:
        proc = thr.get("service_events_processed")
        tail = f"; service processed {proc:,} of {thr['events']:,}" if proc is not None else ""
        out.append(
            (
                "Sustained throughput",
                f"{thr['events_per_second']:,.0f} events/s over {thr['seconds']} s{tail}",
            )
        )
    ov = dig(p, "overall") or {}
    if ov:
        out.append(
            (
                "Attack campaign recall (rule-based)",
                f"{ov['campaign_recall_expected_rule']:.3f} over "
                f"{ov['campaigns_covered']} campaigns in "
                f"{len(ov['covered_scenarios'])} covered scenarios; no rule yet for: "
                f"{', '.join(ov['uncovered_scenarios']) or 'none'}",
            )
        )
    fp = dig(p, "false_positives") or {}
    if fp:
        out.append(
            (
                "False alerts on benign events",
                f"{fp['benign_events_alerted']} of {fp['benign_events']:,} "
                f"(rate {fp['false_positive_rate_event']:.5f})",
            )
        )
    latency = dig(p, "latency") or {}
    out.append(("Time to detect (attack start to alert)", lat(latency.get("time_to_detect"))))
    out.append(("Pipeline latency per detection", lat(latency.get("pipeline_per_detection"))))
    out.append(
        ("Time to respond (attack start to enforcement)", lat(latency.get("time_to_respond")))
    )
    net = dig(m, "ml", "network") or {}
    for name, label in (("rf_binary", "Random Forest"), ("xgb_binary", "XGBoost")):
        r = net.get(name)
        out.append(
            (
                f"Network IDS, {label} (CIC-IDS2017 held-out split)",
                f"F1 {r['f1']:.4f}, precision {r['precision']:.4f}, recall {r['recall']:.4f}, "
                f"FPR {r['false_positive_rate']:.4f}, PR-AUC {r['pr_auc']:.4f}"
                if r
                else TBD,
            )
        )
    mc = net.get("xgb_multi")
    out.append(
        (
            "Network IDS, multi-class XGBoost",
            f"macro-F1 {mc['macro_f1']:.4f}, accuracy {mc['accuracy']:.4f}" if mc else TBD,
        )
    )
    for key, label in (
        ("anomaly", "Anomaly models"),
        ("phishing", "Phishing URL model"),
        ("fraud", "Fraud model"),
    ):
        out.append((label, "measured, see metrics.json" if dig(m, "ml", key) else TBD))
    inj = dig(m, "injection", "pass_rate")
    out.append(("Prompt-injection suite", f"{inj:.0%} on-schema" if inj is not None else TBD))
    out.append(
        ("OWASP findings, v1 to v2", TBD if dig(m, "owasp") is None else str(dig(m, "owasp")))
    )
    out.append(("CI security scanners", TBD if dig(m, "ci") is None else str(dig(m, "ci"))))
    t = dig(m, "tests") or {}
    py, jv = t.get("python_collected"), t.get("java_junit")
    out.append(("Automated tests", f"{py} Python" + (f", {jv} JUnit" if jv else "") if py else TBD))
    return out


def render(m: dict[str, Any]) -> str:
    lines = ["| Metric | Result |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in rows(m)]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--metrics", type=Path, default=Path("results/metrics.json"))
    ap.add_argument("--readme", type=Path, default=Path("README.md"))
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    metrics = json.loads(a.metrics.read_text(encoding="utf-8")) if a.metrics.exists() else {}
    text = a.readme.read_text(encoding="utf-8")
    if START not in text or END not in text:
        print("README has no METRICS markers", file=sys.stderr)
        return 2
    head, rest = text.split(START, 1)
    _, tail = rest.split(END, 1)
    new = f"{head}{START}\n{render(metrics)}\n{END}{tail}"
    if a.check:
        return 0 if new == text else 1
    a.readme.write_text(new, encoding="utf-8")
    print(f"README results updated from {a.metrics}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
