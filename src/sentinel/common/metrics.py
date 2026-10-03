"""Prometheus metrics for the detection and response path.

Label values come only from bounded enums (event source, severity, rule ids, ATT&CK ids, action
outcomes), never from log content, so untrusted input cannot inflate label cardinality.
"""

from prometheus_client import Counter, Histogram

EVENTS = Counter("sentinel_events_total", "Normalized events processed", ["source"])
DETECTIONS = Counter(
    "sentinel_detections_total",
    "Detections emitted",
    ["detector", "attack_id", "severity"],
)
ACTIONS = Counter("sentinel_actions_total", "Response actions by outcome", ["action", "outcome"])
EVENT_SECONDS = Histogram(
    "sentinel_event_processing_seconds",
    "Time to evaluate one event against all detectors",
    buckets=(0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 1.0),
)
RESPONSE_SECONDS = Histogram(
    "sentinel_response_seconds",
    "Time to run every planned action for one detection",
    buckets=(0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5),
)
