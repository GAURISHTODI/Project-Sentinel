"""Detection engine: rules + ML on every event, then publish and respond.

Everything arriving here is untrusted. Raw bytes are validated against the schema (invalid
messages are counted and dropped, never crash the loop), and the evaluation label is stripped
before any detector sees the event.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Sequence
from typing import Protocol

from pydantic import ValidationError

from sentinel.common.logging import get_logger
from sentinel.common.schema import Detection, NormalizedEvent
from sentinel.detect.ml.predictor import NetworkPredictor
from sentinel.detect.rules.engine import RuleEngine
from sentinel.respond.responder import Responder

log = get_logger(__name__)

# Approximate ATT&CK mapping for CIC-IDS2017 classes (an analyst judgement, not ground truth).
CIC_ATTACK_MAP = {
    "PortScan": "T1046",
    "DDoS": "T1499",
    "DoS Hulk": "T1499",
    "DoS GoldenEye": "T1499",
    "DoS slowloris": "T1499",
    "DoS Slowhttptest": "T1499",
    "FTP-Patator": "T1110",
    "SSH-Patator": "T1110",
    "Web Attack Brute Force": "T1110",
    "Web Attack XSS": "T1190",
    "Web Attack SQL Injection": "T1190",
    "Heartbleed": "T1190",
    "Bot": "T1071",
    "Infiltration": "T1078",
}


class Detector(Protocol):
    def evaluate(self, ev: NormalizedEvent) -> list[Detection]: ...


class NetworkMLDetector:
    """Scores network flows that carry CIC-IDS2017-style features; skips everything else."""

    def __init__(self, binary: NetworkPredictor, multi: NetworkPredictor | None = None) -> None:
        self.binary, self.multi = binary, multi

    def evaluate(self, ev: NormalizedEvent) -> list[Detection]:
        if ev.source != "network" or not ev.flow_features:
            return []
        try:
            is_attack, p = self.binary.is_attack(ev.flow_features)
        except (
            ValueError
        ):  # too few CIC features (e.g. generator flows): not scorable, not an error
            return []
        if not is_attack:
            return []
        label, conf = ("unknown", 0.0)
        if self.multi is not None:
            label, conf = self.multi.attack_type(ev.flow_features)
        return [
            Detection(
                event_id=ev.event_id,
                model_name=self.binary.model_name,
                attack_id=CIC_ATTACK_MAP.get(label),
                severity="high" if p >= 0.95 else "medium",
                score=min(p, 0.99),
                timestamp_event=ev.timestamp_generated,
                src_ip=ev.src_ip,
                user=ev.user,
                explanation=(
                    f"Network IDS model flagged this flow: attack probability {p:.3f}; "
                    f"most likely class {label} (confidence {conf:.2f})."
                ),
            )
        ]


class _RuleDetector:
    def __init__(self, rules: RuleEngine) -> None:
        self.rules = rules

    def evaluate(self, ev: NormalizedEvent) -> list[Detection]:
        return self.rules.evaluate(ev)


class DetectionEngine:
    def __init__(self, rules: RuleEngine, extra: Sequence[Detector] | None = None) -> None:
        self.rules = rules
        self.detectors: list[Detector] = [_RuleDetector(rules), *(extra or [])]

    def process(self, ev: NormalizedEvent) -> list[Detection]:
        safe = ev.strip_label()  # defence in depth: detectors never see ground truth
        out: list[Detection] = []
        for d in self.detectors:
            out.extend(d.evaluate(safe))
        return out


class Pipeline:
    """bytes from Kafka -> validated event -> detections -> publish + respond."""

    def __init__(
        self,
        engine: DetectionEngine,
        responder: Responder | None = None,
        publish: Callable[[Detection], None] | None = None,
    ) -> None:
        self.engine, self.responder, self.publish = engine, responder, publish
        self.counts: Counter[str] = Counter()

    def handle_message(self, raw: bytes | str) -> list[Detection]:
        try:
            ev = NormalizedEvent.model_validate_json(raw)
        except ValidationError:
            self.counts["invalid"] += 1  # poison message: drop it, keep the loop alive
            return []
        self.counts["events"] += 1
        dets = self.engine.process(ev)
        for d in dets:
            self.counts["detections"] += 1
            if self.publish is not None:
                self.publish(d)
            if self.responder is not None:
                self.responder.handle(d)
        return dets
