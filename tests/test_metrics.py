import json
import re
from pathlib import Path

from prometheus_client import REGISTRY

from sentinel.common import metrics  # noqa: F401  # registers the Sentinel metric families
from sentinel.detect.engine import DetectionEngine, Pipeline
from sentinel.detect.rules.engine import RuleEngine
from sentinel.detect.rules.state import MemoryStore
from sentinel.generator.core import Generator

DASHBOARD = Path(__file__).parents[1] / "dashboards" / "grafana" / "dashboards" / "sentinel.json"


def _sum(family: str, suffix: str) -> float:
    return sum(
        s.value
        for m in REGISTRY.collect()
        if m.name == family
        for s in m.samples
        if s.name == family + suffix
    )


def test_pipeline_counters_match_pipeline_counts() -> None:
    pipe = Pipeline(DetectionEngine(RuleEngine(MemoryStore())))
    events_before = _sum("sentinel_events", "_total")
    detections_before = _sum("sentinel_detections", "_total")
    for ev in Generator(eps=200, duration=10, attack_ratio=0.2, seed=7).stream():
        pipe.handle_message(ev.strip_label().model_dump_json())
    assert pipe.counts["events"] > 0 and pipe.counts["detections"] > 0
    assert _sum("sentinel_events", "_total") - events_before == pipe.counts["events"]
    assert _sum("sentinel_detections", "_total") - detections_before == pipe.counts["detections"]


def test_every_metric_on_the_grafana_dashboard_is_exported() -> None:
    dash = json.loads(DASHBOARD.read_text(encoding="utf-8"))
    exprs = [t["expr"] for p in dash["panels"] for t in p["targets"]]
    families = {m.name for m in REGISTRY.collect()}
    referenced = set(re.findall(r"sentinel_[a-z_]+", " ".join(exprs)))
    assert referenced
    for name in referenced:
        family = re.sub(r"_(total|bucket|sum|count)$", "", name)
        assert family in families, name
    for panel in dash["panels"]:
        assert panel["datasource"]["uid"] == "prometheus"
