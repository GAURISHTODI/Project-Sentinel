import numpy as np
import pytest

from sentinel.common.schema import NormalizedEvent
from sentinel.detect.engine import FraudDetector
from sentinel.detect.ml.predictor import DEFAULT_FRAUD_DIR, FraudPredictor
from sentinel.detect.ml.train_fraud import FEATURES, at_threshold, pick_threshold


class FakePredictor:
    model_name = "fraud-xgb"
    threshold = 0.5

    def fraud_probability(self, features: dict[str, float]) -> float:
        return 0.97 if features.get("V1", 0.0) > 2.0 else 0.01


def txn(v1: float, event_type: str = "transaction") -> NormalizedEvent:
    flow = {"Time": 10.0, "V1": v1, "Amount": 42.0}
    return NormalizedEvent(
        source="app", event_type=event_type, src_ip="203.0.113.9", user="bob",
        amount=42.0, flow_features=flow,
    )  # fmt: skip


def test_fraudulent_transaction_is_flagged_with_attack_mapping() -> None:
    [d] = FraudDetector(FakePredictor()).evaluate(txn(5.0))
    assert d.model_name == "fraud-xgb" and d.attack_id == "T1657"
    assert d.severity == "high" and d.score == pytest.approx(0.97)


def test_non_transaction_and_normal_transactions_are_not_flagged() -> None:
    det = FraudDetector(FakePredictor())
    assert det.evaluate(txn(5.0, event_type="http_request")) == []
    assert det.evaluate(txn(0.1)) == []


def test_missing_features_are_skipped_not_raised() -> None:
    ev = NormalizedEvent(source="app", event_type="transaction", flow_features={"Time": 1.0})
    assert FraudDetector(FakePredictor()).evaluate(ev) == []


def test_predictor_rejects_missing_and_non_finite_features() -> None:
    pred = FraudPredictor.__new__(FraudPredictor)
    pred.features = list(FEATURES)
    pred._model = None  # never reached: validation fails first
    with pytest.raises(ValueError, match="missing"):
        pred.fraud_probability({"Time": 1.0})
    bad = {f: 0.0 for f in FEATURES} | {"V1": float("nan")}
    with pytest.raises(ValueError, match="non-finite"):
        pred.fraud_probability(bad)


def test_threshold_is_chosen_on_validation_scores_only() -> None:
    y = np.array([0, 0, 0, 0, 1, 1])
    prob = np.array([0.1, 0.2, 0.3, 0.4, 0.6, 0.9])
    thr = pick_threshold(y, prob, target_precision=1.0)
    assert thr is not None and thr == pytest.approx(0.6)
    assert pick_threshold(y, prob, target_precision=1.01) is None


def test_at_threshold_reports_precision_recall_and_fpr() -> None:
    y = np.array([0, 0, 1, 1])
    prob = np.array([0.2, 0.7, 0.8, 0.3])
    res = at_threshold(y, prob, 0.5)
    assert res["precision"] == pytest.approx(0.5)
    assert res["recall"] == pytest.approx(0.5)
    assert res["false_positive_rate"] == pytest.approx(0.5)


@pytest.mark.skipif(
    not (DEFAULT_FRAUD_DIR / "fraud_model.joblib").exists(), reason="no trained model"
)
def test_real_model_scores_a_large_outlier_higher_than_a_typical_row() -> None:
    pred = FraudPredictor()
    typical = {f: 0.0 for f in FEATURES}
    outlier = typical | {"V14": -20.0, "V17": -15.0, "Amount": 900.0}
    assert pred.fraud_probability(outlier) > pred.fraud_probability(typical)
