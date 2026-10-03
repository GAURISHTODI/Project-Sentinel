import pytest

from sentinel.common.schema import NormalizedEvent
from sentinel.detect.engine import DetectionEngine, PhishingURLDetector
from sentinel.detect.ml.predictor import DEFAULT_PHISHING_DIR, PhishingPredictor
from sentinel.detect.rules.engine import RuleEngine
from sentinel.detect.rules.state import MemoryStore


class FakePredictor:
    model_name = "phishing-url"
    threshold = 0.5

    def phishing_probability(self, url: str) -> float:
        return 0.95 if "evil" in url else 0.1


def event(url: str | None, label: str | None = None) -> NormalizedEvent:
    return NormalizedEvent(
        source="app",
        event_type="http_request",
        src_ip="203.0.113.7",
        user="alice",
        url=url,
        label=label,
    )


def test_phishing_url_produces_detection_with_attack_mapping() -> None:
    [d] = PhishingURLDetector(FakePredictor()).evaluate(event("http://evil.example/login"))
    assert d.model_name == "phishing-url"
    assert d.attack_id == "T1566"
    assert d.severity == "high" and d.score == pytest.approx(0.95)
    assert d.src_ip == "203.0.113.7" and d.user == "alice"


def test_benign_or_missing_url_is_not_flagged() -> None:
    det = PhishingURLDetector(FakePredictor())
    assert det.evaluate(event("https://good.example/")) == []
    assert det.evaluate(event(None)) == []


def test_explanation_shows_host_only_and_strips_control_text() -> None:
    hostile = "http://evil.example/\x1b[31mpay\nload?token=SECRET" + "a" * 3000
    [d] = PhishingURLDetector(FakePredictor()).evaluate(event(hostile))
    assert (
        "SECRET" not in d.explanation and "\n" not in d.explanation and "\x1b" not in d.explanation
    )
    assert len(d.explanation) < 300


def test_detector_never_sees_the_evaluation_label() -> None:
    seen: list[str | None] = []

    class Spy(FakePredictor):
        def phishing_probability(self, url: str) -> float:
            seen.append(url)
            return 0.1

    engine = DetectionEngine(RuleEngine(MemoryStore()), [PhishingURLDetector(Spy())])
    engine.process(event("http://evil.example/", label="phishing"))
    assert seen == ["http://evil.example/"]


@pytest.mark.skipif(
    not (DEFAULT_PHISHING_DIR / "url_model.joblib").exists(), reason="no trained model"
)
def test_real_model_scores_obvious_phishing_above_plain_homepage() -> None:
    pred = PhishingPredictor()
    assert pred.phishing_probability(
        "http://192.168.4.7:8080/secure/verify/account/login.php?x=1"
    ) > (pred.phishing_probability("https://www.python.org/"))
