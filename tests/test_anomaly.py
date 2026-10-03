import numpy as np
import pandas as pd
import pytest

from sentinel.detect.ml.data import BENIGN, LABEL
from sentinel.detect.ml.train_anomaly import benign_fit_and_val, evaluate, pick_threshold, train


def synthetic(seed: int = 3) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    benign = rng.normal(0.0, 1.0, size=(3000, 6))
    dos = rng.normal(5.0, 1.0, size=(150, 6))
    scan = rng.normal(-5.0, 1.0, size=(150, 6))
    X = np.vstack([benign, dos, scan]).astype(np.float32)
    labels = [BENIGN] * 3000 + ["DoS"] * 150 + ["PortScan"] * 150
    df = pd.DataFrame(X, columns=[f"f{i}" for i in range(6)])
    df[LABEL] = labels
    return df


def test_fit_and_validation_rows_are_benign_only() -> None:
    df = synthetic()
    X, y = df.drop(columns=[LABEL]), df[LABEL]
    fit, val = benign_fit_and_val(X, y, seed=1)
    assert len(fit) > 0 and len(val) > 0
    benign_idx = set(df.index[df[LABEL] == BENIGN])
    assert set(fit.index) <= benign_idx
    assert set(val.index) <= benign_idx
    assert not set(fit.index) & set(val.index)


def test_threshold_uses_only_the_requested_benign_quantile() -> None:
    scores = np.arange(1000, dtype=float)
    assert pick_threshold(scores, target_fpr=0.01) == pytest.approx(989.01)


def test_evaluate_reports_fpr_and_per_class_detection() -> None:
    scores = np.array([0.1, 0.2, 0.9, 0.95, 0.3, 0.97])
    y = np.array([0, 0, 1, 1, 0, 1])
    labels = np.array([BENIGN, BENIGN, "DoS", "PortScan", BENIGN, "DoS"])
    res = evaluate(scores, threshold=0.5, y_attack=y, labels=labels)
    assert res["false_positive_rate"] == 0.0
    assert res["recall"] == 1.0
    assert res["detection_rate_by_class"] == {"DoS": 1.0, "PortScan": 1.0}


def test_both_anomaly_models_separate_synthetic_attacks(tmp_path) -> None:  # type: ignore[no-untyped-def]
    out = train(synthetic(), None, tmp_path / "m", results_dir=tmp_path / "r", seed=5, epochs=3)
    for name in ("isolation_forest", "autoencoder"):
        r = out["results"][name]
        assert r["roc_auc"] > 0.95, name
        assert r["false_positive_rate"] < 0.05, name
        assert all(rate > 0.9 for rate in r["detection_rate_by_class"].values()), name
    assert (tmp_path / "r" / "anomaly.json").exists()
    assert out["card"]["split"]["benign_validation_rows"] > 0
