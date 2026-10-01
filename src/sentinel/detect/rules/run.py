"""Replay a JSONL event file through the rule engine: python -m sentinel.detect.rules.run FILE.

The label is read ONLY for the summary table; the engine receives label-stripped events.
"""

from __future__ import annotations

import argparse
import time
from collections import Counter, defaultdict
from pathlib import Path

from sentinel.common.schema import Detection, NormalizedEvent
from sentinel.detect.rules.engine import RuleEngine
from sentinel.detect.rules.state import MemoryStore


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Replay events through the Sentinel rule engine")
    ap.add_argument("input", type=Path, help="JSONL produced by sentinel.generator.run")
    ap.add_argument("--show", type=int, default=3, help="example detections to print")
    a = ap.parse_args(argv)

    engine = RuleEngine(MemoryStore())
    by_rule: Counter[str] = Counter()
    by_label: dict[str, Counter[str]] = defaultdict(Counter)
    examples: list[Detection] = []
    n = 0
    t0 = time.perf_counter()
    with a.input.open(encoding="utf-8") as fh:
        for line in fh:
            ev = NormalizedEvent.model_validate_json(line)
            n += 1
            for d in engine.evaluate(ev.strip_label()):
                by_rule[str(d.rule_id)] += 1
                by_label[ev.label or "?"][str(d.rule_id)] += 1
                if len(examples) < a.show:
                    examples.append(d)
    elapsed = time.perf_counter() - t0
    print(f"{n} events, {sum(by_rule.values())} detections, {n / elapsed:,.0f} events/s")
    titles = {r.id: f"{r.title} ({r.attack_id})" for r in engine.rules}
    for rule_id in sorted(by_rule):
        print(f"  {rule_id}  {by_rule[rule_id]:6d}  {titles[rule_id]}")
    print("\nlabel of triggering event -> rules fired")
    for label in sorted(by_label):
        print(f"  {label:22s}{dict(by_label[label])}")
    print("\nexamples:")
    for d in examples:
        print(f"  [{d.severity}] {d.rule_id} score={d.score:.2f} {d.explanation}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
