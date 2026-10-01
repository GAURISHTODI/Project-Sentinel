"""CLI: python -m sentinel.generator.run --eps 1000 --duration 60 [--sink kafka|jsonl|stdout]."""

from __future__ import annotations

import argparse
import sys
import time
from collections import Counter
from collections.abc import Callable
from pathlib import Path

from sentinel.common.config import get_settings
from sentinel.common.schema import NormalizedEvent
from sentinel.generator.core import Generator, parse_mix
from sentinel.generator.scenarios import ATTACKS


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Sentinel synthetic log generator")
    ap.add_argument("--eps", type=int, default=1000, help="events per second")
    ap.add_argument("--duration", type=int, default=60, help="seconds of traffic")
    ap.add_argument("--attack-ratio", type=float, default=0.10, help="fraction of attack events")
    ap.add_argument(
        "--attack-mix", default=None, help=f"weights such as sqli=3,dos=1; from {sorted(ATTACKS)}"
    )
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--sink", choices=["kafka", "jsonl", "stdout"], default="kafka")
    ap.add_argument("--out", type=Path, default=Path("data/events.jsonl"))
    ap.add_argument("--fast", action="store_true", help="do not pace in real time")
    a = ap.parse_args(argv)

    gen = Generator(a.eps, a.duration, a.seed, a.attack_ratio, parse_mix(a.attack_mix))
    close: Callable[[], None] = lambda: None  # noqa: E731
    emit: Callable[[NormalizedEvent], None]
    if a.sink == "kafka":
        from sentinel.ingest.producer import EventProducer

        cfg = get_settings()
        prod = EventProducer(cfg.kafka_bootstrap, cfg.events_topic)
        emit, close = prod.send, prod.flush
    elif a.sink == "jsonl":
        a.out.parent.mkdir(parents=True, exist_ok=True)
        fh = a.out.open("w", encoding="utf-8")

        def emit(ev: NormalizedEvent) -> None:
            fh.write(ev.model_dump_json() + "\n")

        close = fh.close
    else:

        def emit(ev: NormalizedEvent) -> None:
            sys.stdout.write(ev.model_dump_json() + "\n")

    counts: Counter[str] = Counter()
    t0 = time.time()
    for sec, batch in gen.batches(t0):
        if not a.fast:  # real-time pacing; stamp events with the actual emission time
            delay = t0 + sec - time.time()
            if delay > 0:
                time.sleep(delay)
        for ev in batch:
            if not a.fast:
                ev.timestamp_generated = time.time()
            counts[ev.label or "unlabeled"] += 1
            emit(ev)
    close()
    elapsed = time.time() - t0
    total = sum(counts.values())
    print(f"emitted {total} events in {elapsed:.1f}s ({total / elapsed:.0f} eps)", file=sys.stderr)
    for label, n in counts.most_common():
        print(f"  {label:22s}{n:8d}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
