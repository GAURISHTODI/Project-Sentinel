"""Kafka detection service: python -m sentinel.detect.run [--idle-exit 10] [--from-beginning]."""

from __future__ import annotations

import argparse
import sys
import time
from collections.abc import Callable

import redis

from sentinel.common.config import get_settings
from sentinel.common.logging import get_logger
from sentinel.detect.engine import DetectionEngine, NetworkMLDetector, Pipeline
from sentinel.detect.ml.predictor import DEFAULT_DIR, NetworkPredictor
from sentinel.detect.rules.engine import RuleEngine
from sentinel.detect.rules.state import CachedStore, RedisStore
from sentinel.ingest.producer import EventProducer
from sentinel.respond.actions import Actions
from sentinel.respond.notify import Notifier
from sentinel.respond.policy import load_policy
from sentinel.respond.repo import PgRepo
from sentinel.respond.responder import Responder

log = get_logger(__name__)


def build_pipeline(
    use_ml: bool = True,
) -> tuple[Pipeline, EventProducer, PgRepo, Callable[[], None]]:
    cfg = get_settings()
    r = redis.Redis.from_url(cfg.redis_url.get_secret_value(), decode_responses=True)
    store = CachedStore(RedisStore(r))  # partition-local windows, batched write-behind to Redis
    rules = RuleEngine(store)
    extra = []
    if use_ml and (DEFAULT_DIR / "xgb_binary.joblib").exists():
        multi_path = DEFAULT_DIR / "xgb_multi.joblib"
        multi = NetworkPredictor(DEFAULT_DIR, "xgb_multi") if multi_path.exists() else None
        extra.append(NetworkMLDetector(NetworkPredictor(DEFAULT_DIR, "xgb_binary"), multi))
    repo = PgRepo(cfg.database_url.get_secret_value())
    policy = load_policy()
    notifier = Notifier(cfg.webhook_url.get_secret_value() or None, cfg.webhook_flavor)
    responder = Responder(
        policy,
        Actions(r, repo, notifier, policy),
        repo,
        store,
        {rule.id: rule.response for rule in rules.rules},
    )
    det_out = EventProducer(cfg.kafka_bootstrap, cfg.detections_topic)
    pipe = Pipeline(
        DetectionEngine(rules, extra),
        responder,
        lambda d: det_out.send_model(d, d.src_ip or d.event_id),
    )

    def flush_all() -> None:
        store.flush()
        responder.flush()
        det_out.poll()

    return pipe, det_out, repo, flush_all


def main(argv: list[str] | None = None) -> int:
    from confluent_kafka import Consumer

    ap = argparse.ArgumentParser(description="Sentinel detection + response service")
    ap.add_argument("--group", default="sentinel-detect")
    ap.add_argument("--from-beginning", action="store_true")
    ap.add_argument(
        "--idle-exit",
        type=float,
        default=0.0,
        help="exit after N idle seconds, counted from the first message",
    )
    ap.add_argument(
        "--max-wait",
        type=float,
        default=300.0,
        help="with --idle-exit: give up if no message arrives within N seconds",
    )
    ap.add_argument("--no-ml", action="store_true")
    a = ap.parse_args(argv)

    cfg = get_settings()
    pipe, det_out, repo, flush_all = build_pipeline(use_ml=not a.no_ml)
    consumer = Consumer(
        {
            "bootstrap.servers": cfg.kafka_bootstrap,
            "group.id": a.group,
            "auto.offset.reset": "earliest" if a.from_beginning else "latest",
            "enable.auto.commit": False,
        }
    )
    consumer.subscribe([cfg.events_topic])
    started = last_msg = time.time()
    seen_any = False
    uncommitted = 0
    try:
        while True:
            msg = consumer.poll(0.5)
            if msg is None or msg.error():
                flush_all()  # idle: push batched state out
                if a.idle_exit and seen_any and time.time() - last_msg > a.idle_exit:
                    break
                if a.idle_exit and not seen_any and time.time() - started > a.max_wait:
                    break
                continue
            seen_any = True
            last_msg = time.time()
            payload = msg.value()
            if payload is not None:
                pipe.handle_message(payload)
            uncommitted += 1
            if uncommitted % 200 == 0:
                flush_all()
            if uncommitted >= 500:
                consumer.commit(asynchronous=False)
                uncommitted = 0
    except KeyboardInterrupt:
        pass
    finally:
        if uncommitted:
            consumer.commit(asynchronous=False)
        consumer.close()
        flush_all()
        det_out.flush()
        repo.close()
    print(dict(pipe.counts), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
