"""Run a labeled scenario through the real pipeline and write results/metrics.json.

    python -m sentinel.eval.evaluate                      # live if the compose core stack is up
    python -m sentinel.eval.evaluate --mode inproc        # no Docker; logic metrics only

Every number in the README comes from the JSON this writes (hard rule 1). A section that has not
been measured yet is simply absent and shows as TBD.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import subprocess
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sentinel.common.config import get_settings
from sentinel.common.schema import Detection
from sentinel.detect.rules.engine import RuleEngine, load_rules
from sentinel.eval.metrics import Response, RunData, compute
from sentinel.generator.core import Generator

RESULTS = Path("results")


# ------------------------------------------------------------------ in-process run (no Docker)


def run_inproc(eps: int, duration: int, seed: int, ratio: float) -> RunData:
    import fakeredis

    from sentinel.detect.engine import DetectionEngine, Pipeline
    from sentinel.detect.rules.state import MemoryStore
    from sentinel.respond.actions import Actions
    from sentinel.respond.notify import Notifier
    from sentinel.respond.policy import load_policy
    from sentinel.respond.repo import MemoryRepo
    from sentinel.respond.responder import Responder

    store, repo, policy = MemoryStore(), MemoryRepo(), load_policy()
    rules = RuleEngine(store)
    actions = Actions(fakeredis.FakeRedis(decode_responses=True), repo, Notifier(None), policy)
    responder = Responder(policy, actions, repo, store, {r.id: r.response for r in rules.rules})
    responses: list[Response] = []
    handle = responder.handle

    def recording(det: Detection) -> list[Any]:
        out = handle(det)
        responses.extend(Response(det.event_id, r.action, r.outcome.value, r.ts) for r in out)
        return out

    responder.handle = recording  # type: ignore[method-assign]
    pipe = Pipeline(DetectionEngine(rules), responder)
    events = list(Generator(eps, duration, seed, ratio).stream())
    detections: list[Detection] = []
    t0 = time.perf_counter()
    for ev in events:
        detections.extend(pipe.handle_message(ev.strip_label().model_dump_json()))
    responder.flush()
    return RunData(events, detections, responses, time.perf_counter() - t0, realtime=False)


# ------------------------------------------------------------------ live run (real services)


def _create_topics(bootstrap: str, names: list[str]) -> None:
    from confluent_kafka.admin import AdminClient
    from confluent_kafka.cimpl import NewTopic

    admin = AdminClient({"bootstrap.servers": bootstrap})
    for name, fut in admin.create_topics([NewTopic(n, 1, 1) for n in names]).items():
        try:
            fut.result(timeout=15)
        except Exception as exc:  # noqa: BLE001  # confluent raises KafkaException; any failure is fatal
            raise RuntimeError(f"could not create topic {name}: {exc}") from exc


def _parse_counts(stderr_tail: str) -> dict[str, int]:
    """The service prints its final counters as a dict on the last line of stderr."""
    for line in reversed(stderr_tail.strip().splitlines()):
        if line.startswith("{") and "events" in line:
            try:
                return {str(k): int(v) for k, v in ast.literal_eval(line).items()}
            except (ValueError, SyntaxError):
                return {}
    return {}


def services_up() -> bool:
    import psycopg
    import redis
    from confluent_kafka import Consumer

    cfg = get_settings()
    try:
        redis.Redis.from_url(cfg.redis_url.get_secret_value(), socket_connect_timeout=1).ping()
        psycopg.connect(cfg.database_url.get_secret_value(), connect_timeout=2).close()
        c = Consumer({"bootstrap.servers": cfg.kafka_bootstrap, "group.id": "probe"})
        c.list_topics(timeout=3)
        c.close()
    except Exception:  # noqa: BLE001  # any failure means "not up"; the caller falls back
        return False
    return True


def run_live(eps: int, duration: int, seed: int, ratio: float) -> RunData:
    import psycopg
    import redis
    from confluent_kafka import Consumer

    from sentinel.ingest.producer import EventProducer

    cfg = get_settings()
    r = redis.Redis.from_url(cfg.redis_url.get_secret_value(), decode_responses=True)
    for key in r.scan_iter("sen:*"):  # evaluation owns these keys: start from a clean slate
        r.delete(key)
    with psycopg.connect(cfg.database_url.get_secret_value(), autocommit=True) as pg:
        pg.execute("DELETE FROM incidents")
        pg.execute("DELETE FROM locked_accounts")

    group = f"eval-{uuid.uuid4().hex[:8]}"
    # fresh topics per run + read-from-beginning: no start-up race, nothing left from earlier runs
    events_topic, dets_topic = f"events.eval.{group}", f"detections.eval.{group}"
    env = {**os.environ, "EVENTS_TOPIC": events_topic, "DETECTIONS_TOPIC": dets_topic}
    _create_topics(cfg.kafka_bootstrap, [events_topic, dets_topic])  # must exist before assignment
    svc = subprocess.Popen(  # noqa: S603  # fixed argv, no shell
        [sys.executable, "-m", "sentinel.detect.run", "--group", group, "--from-beginning",
         "--idle-exit", "10"],
        stderr=subprocess.PIPE, stdout=subprocess.DEVNULL, text=True, env=env,
    )  # fmt: skip
    if svc.stderr is None:
        raise RuntimeError("service stderr not captured")
    deadline = time.time() + 90
    for line in svc.stderr:  # block until the consumer has joined its group
        if line.startswith("READY"):
            break
        if time.time() > deadline:
            svc.kill()
            raise RuntimeError("detection service did not become ready")

    start_dt = datetime.now(UTC)
    prod = EventProducer(cfg.kafka_bootstrap, events_topic)
    gen = Generator(eps, duration, seed, ratio)
    events = []
    t0 = time.time()
    for sec, batch in gen.batches(t0):
        delay = t0 + sec - time.time()
        if delay > 0:
            time.sleep(delay)
        for ev in batch:
            ev.timestamp_generated = time.time()  # stamped at emission: latency includes Kafka
            events.append(ev)
            prod.send(ev.strip_label())  # the pipeline never receives the label
    prod.flush()
    wall = time.time() - t0
    svc.wait(timeout=180)
    counts = _parse_counts(svc.stderr.read())
    if counts.get("events") != len(events):
        raise RuntimeError(f"service processed {counts.get('events')} of {len(events)} events")

    dets: list[Detection] = []
    c = Consumer({"bootstrap.servers": cfg.kafka_bootstrap, "group.id": f"read-{group}",
                  "auto.offset.reset": "earliest"})  # fmt: skip
    c.subscribe([dets_topic])
    idle = time.time()
    while time.time() - idle < 5:
        m = c.poll(1.0)
        if m is None or m.error():
            continue
        idle = time.time()
        payload = m.value()
        if payload is None:
            continue
        d = Detection.model_validate_json(payload)
        if d.timestamp_detected >= start_dt.timestamp():
            dets.append(d)
    c.close()

    with psycopg.connect(cfg.database_url.get_secret_value()) as pg:
        rows = pg.execute(
            "SELECT detail->>'event_id', action, detail->>'outcome', extract(epoch FROM ts) "
            "FROM audit_log WHERE actor = 'sentinel-responder' AND ts >= %s", (start_dt,),
        ).fetchall()  # fmt: skip
    responses = [Response(str(a), str(b), str(o), float(t)) for a, b, o, t in rows if a]
    return RunData(events, dets, responses, wall, realtime=True, service_counts=counts)


# ------------------------------------------------------------------ sections from other tasks


def _git_commit() -> str | None:
    """Short commit hash, suffixed '+dirty' when the working tree has uncommitted changes."""
    try:
        head = subprocess.run(  # noqa: S603
            ["git", "rev-parse", "--short", "HEAD"],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        dirty = subprocess.run(  # noqa: S603
            ["git", "status", "--porcelain", "--untracked-files=no"],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    return f"{head}+dirty" if dirty else head or None


def _count_tests() -> dict[str, Any]:
    out = subprocess.run(  # noqa: S603
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-o", "addopts="],
        capture_output=True,
        text=True,
    )
    m = re.search(r"(\d+) tests? collected", out.stdout) or re.search(r"(\d+) tests?", out.stdout)
    return {"python_collected": int(m.group(1)) if m else None,
            "java_junit": None}  # filled when the Spring Boot modules exist (T7/T8)  # fmt: skip


def collect_sections() -> dict[str, Any]:
    """Merge results written by other tasks' scripts, so a fresh evaluate.py run never loses them.

    results/ml/*.json         -> metrics['ml'][name]     one file per model (T4/T15/T16/T17);
                                                          read by name, e.g. dig(m, "ml", "network")
    results/owasp/summary.json -> metrics['owasp']        one file, the whole section (T10)
    results/ci/summary.json   -> metrics['ci']           one file, the whole section (T20)

    Anything hand-added directly to metrics.json instead of one of these files is silently
    discarded the next time this runs -- write the results/<section>/ file instead.
    """
    out: dict[str, Any] = {}
    ml_dir = RESULTS / "ml"
    if ml_dir.exists() and list(ml_dir.glob("*.json")):
        out["ml"] = {
            p.stem: json.loads(p.read_text(encoding="utf-8")) for p in sorted(ml_dir.glob("*.json"))
        }
    for section in ("owasp", "ci"):
        summary = RESULTS / section / "summary.json"
        if summary.exists():
            out[section] = json.loads(summary.read_text(encoding="utf-8"))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Sentinel evaluation harness")
    ap.add_argument("--mode", choices=["auto", "live", "inproc"], default="auto")
    ap.add_argument("--eps", type=int, default=1000)
    ap.add_argument("--duration", type=int, default=60)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--attack-ratio", type=float, default=0.10)
    ap.add_argument("--out", type=Path, default=RESULTS / "metrics.json")
    a = ap.parse_args(argv)

    mode = a.mode
    if mode == "auto":
        mode = "live" if services_up() else "inproc"
        print(f"mode: {mode}", file=sys.stderr)
    run = (run_live if mode == "live" else run_inproc)(a.eps, a.duration, a.seed, a.attack_ratio)

    from sentinel.detect.rules.engine import DEFAULT_RULES_DIR

    rules = load_rules(DEFAULT_RULES_DIR)
    result = compute(run, {r.id for r in rules})
    metrics: dict[str, Any] = {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "git_commit": _git_commit(),
        "config": {
            "mode": mode,
            "eps": a.eps,
            "duration_s": a.duration,
            "seed": a.seed,
            "attack_ratio": a.attack_ratio,
        },  # fmt: skip
        "pipeline": result,
        "rules": {
            "count": len(rules),
            "attack_techniques": sorted({r.attack_id for r in rules}),
            "technique_count": len({r.attack_id for r in rules}),
        },  # fmt: skip
        "tests": _count_tests(),
        **collect_sections(),
    }
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    _print_summary(metrics)
    return 0


def _print_summary(m: dict[str, Any]) -> None:
    p = m["pipeline"]
    print(f"\nmode={m['config']['mode']} events={p['events']} campaigns={p['campaigns']} "
          f"detections={p['detections']} commit={m['git_commit']}")  # fmt: skip
    print(f"{'scenario':22s}{'campaigns':>10s}{'by expected rule':>18s}{'recall':>9s}")
    for k, v in sorted(p["scenarios"].items()):
        tag = "" if v["covered"] else "  (no rule yet)"
        print(
            f"{k:22s}{v['campaigns']:10d}{v['detected_expected']:18d}{v['recall_expected_rule']:9.2f}{tag}"
        )
    print(
        "campaign recall over covered scenarios: "
        f"{p['overall']['campaign_recall_expected_rule']:.3f}"
    )
    fp = p["false_positives"]
    print(f"benign events alerted: {fp['benign_events_alerted']} / {fp['benign_events']} "
          f"(FPR {fp['false_positive_rate_event']:.5f}) by rule {fp['by_rule']}")  # fmt: skip
    lat = p["latency"]
    print("time-to-detect (attack start -> alert):", lat["time_to_detect"] or lat["note"])
    print("pipeline latency per detection:", lat.get("pipeline_per_detection") or lat["note"])
    print("time-to-respond:", lat["time_to_respond"] or lat["note"])
    print("throughput:", p["throughput"], "\nwritten to results/metrics.json")


if __name__ == "__main__":
    raise SystemExit(main())
