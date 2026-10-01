import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from sentinel.detect.ml.data import (
    BENIGN,
    LABEL,
    drop_redundant_columns,
    load_cicids,
    normalize_label,
    plan_targets,
)
from sentinel.detect.ml.predictor import NetworkPredictor
from sentinel.detect.ml.train_network import split_data, train

FEATS = [f" feat{i}" for i in range(10)]  # real CIC headers have a leading space


def _fake_csv(path: Path, seed: int, n: int = 1500) -> None:
    """A CIC-shaped file: messy header, inf/NaN, duplicates, mojibake label, a rare class."""
    rng = np.random.default_rng(seed)
    classes = {BENIGN: 0.0, "DoS Hulk": 4.0, "PortScan": -4.0}
    rows = []
    for label, shift in classes.items():
        k = n if label == BENIGN else n // 3
        x = rng.normal(shift, 1.0, size=(k, len(FEATS))).astype(np.float32)
        rows.append(pd.DataFrame(x, columns=FEATS).assign(**{" Label": label}))
    rare = pd.DataFrame(rng.normal(8, 1, size=(30, len(FEATS))), columns=FEATS)
    rows.append(rare.assign(**{" Label": "Web Attack \x96 XSS"}))
    df = pd.concat(rows, ignore_index=True)
    df.loc[3, FEATS[0]] = np.inf
    df.loc[7, FEATS[1]] = np.nan
    df[" feat_copy"] = df[FEATS[2]]  # exact duplicate column, like 'Fwd Header Length.1'
    df["const"] = 5.0  # constant column
    df = pd.concat([df, df.iloc[10:20]])  # duplicate rows
    df.to_csv(path, index=False, encoding="latin-1")


@pytest.fixture
def data_dir(tmp_path: Path) -> Path:
    d = tmp_path / "cic"
    d.mkdir()
    _fake_csv(d / "Monday.csv", 1)
    _fake_csv(d / "Tuesday.csv", 2)
    return d


# ------------------------------------------------------------------ loader


def test_label_normalisation_repairs_mojibake() -> None:
    assert normalize_label("Web Attack \x96 XSS") == "Web Attack XSS"
    assert normalize_label("Web Attack � Sql Injection") == "Web Attack SQL Injection"
    assert normalize_label(" BENIGN ") == "BENIGN"
    assert normalize_label("DoS Hulk") == "DoS Hulk"


def test_plan_targets_floor_and_total() -> None:
    counts = {"BENIGN": 1_000_000, "Big": 100_000, "Rare": 11}
    t = plan_targets(counts, sample=10_000, min_per_class=100)
    assert t["Rare"] == 11  # fewer than the floor: keep all of them
    assert sum(t.values()) == 10_000
    assert plan_targets(counts, sample=10**9, min_per_class=100) == counts


def test_loader_cleans_and_samples(data_dir: Path) -> None:
    df, rep = load_cicids(data_dir, sample=1500, seed=42, min_per_class=20)
    feats = [c for c in df.columns if c != LABEL]
    assert all(df[c].dtype == np.float32 for c in feats)
    assert not df[feats].isin([np.inf, -np.inf]).any().any() and not df.isna().any().any()
    assert all(c == c.strip() for c in df.columns)
    assert rep.dropped_non_finite == 4 and rep.dropped_duplicates > 0  # 2 files x (inf + nan)
    assert {" feat_copy", "const"} & set(rep.dropped_columns) or {"feat_copy", "const"} <= set(
        rep.dropped_columns
    )
    assert "Web Attack XSS" in set(df[LABEL])
    assert len(df) == pytest.approx(1500, abs=5)
    assert rep.raw_rows == 2 * (1500 + 500 + 500 + 30 + 10)
    assert not df.duplicated().any()


def test_loader_keeps_rare_class_and_is_deterministic(data_dir: Path) -> None:
    a, _ = load_cicids(data_dir, sample=800, seed=7, min_per_class=20)
    b, _ = load_cicids(data_dir, sample=800, seed=7, min_per_class=20)
    pd.testing.assert_frame_equal(a, b)
    assert (a[LABEL] == "Web Attack XSS").sum() >= 20 - 2  # floor protected it from the 0.4% share


def test_loader_errors_on_empty_dir(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_cicids(tmp_path)


def test_drop_redundant_columns() -> None:
    df = pd.DataFrame(
        {"a": [1, 2, 3], "b": [1, 2, 3], "c": [9, 9, 9], "d": [3, 1, 2], LABEL: list("xyz")}
    )
    out, dropped = drop_redundant_columns(df)
    assert set(dropped) == {"b", "c"} and list(out.columns) == ["a", "d", LABEL]


# ------------------------------------------------------------------ split before scale


def test_split_is_stratified_disjoint_and_leak_free(data_dir: Path) -> None:
    df, _ = load_cicids(data_dir, sample=1500, min_per_class=20)
    X_tr, X_te, y_tr, y_te = split_data(df, seed=42)
    assert set(X_tr.index).isdisjoint(X_te.index)
    assert len(X_tr) + len(X_te) == len(df)
    merged = pd.concat([X_tr, X_te])
    assert not merged.duplicated().any()  # no flow in both splits
    for cls in df[LABEL].unique():  # every class appears on both sides in ~80/20 proportion
        share = (y_te == cls).sum() / (df[LABEL] == cls).sum()
        assert 0.1 <= share <= 0.3


def test_scaler_is_fit_on_train_only(data_dir: Path, tmp_path: Path) -> None:
    df, rep = load_cicids(data_dir, sample=1500, min_per_class=20)
    X_tr, X_te, _, _ = split_data(df, seed=42)
    train(df, rep, tmp_path / "m", rf_trees=5, xgb_trees=5, n_jobs=1, min_multi_support=10)
    import joblib

    scaler = joblib.load(tmp_path / "m" / "rf_binary.joblib")["pipeline"].named_steps["scale"]
    np.testing.assert_allclose(
        scaler.mean_, X_tr.to_numpy(dtype=np.float64).mean(axis=0), rtol=1e-4
    )
    full_mean = df.drop(columns=[LABEL]).to_numpy(dtype=np.float64).mean(axis=0)
    assert not np.allclose(scaler.mean_, full_mean, rtol=1e-9)  # it did NOT see the test rows
    assert len(X_te) > 0


# ------------------------------------------------------------------ training + predictor


@pytest.fixture
def trained(data_dir: Path, tmp_path: Path) -> tuple[Path, dict[str, object]]:
    df, rep = load_cicids(data_dir, sample=1500, min_per_class=20)
    out = tmp_path / "models"
    res = train(
        df, rep, out, tmp_path / "res", tmp_path / "plots", rf_trees=20, xgb_trees=20,
        n_jobs=1, min_multi_support=10, dataset_source="unit-test fake data",
    )  # fmt: skip
    return out, res


def test_training_outputs(trained: tuple[Path, dict[str, object]], tmp_path: Path) -> None:
    out, res = trained
    for f in ("rf_binary", "xgb_binary", "xgb_multi"):
        assert (out / f"{f}.joblib").exists()
    card = json.loads((out / "model_card.json").read_text())
    assert card["seed"] == 42 and card["sample_size"] > 0
    assert card["dataset"]["source"] == "unit-test fake data"
    assert card["split"]["scaler_fit_on"] == "train split only"
    assert card["limitations"] and "xgb_binary" in card["metrics"]
    assert (tmp_path / "res" / "network.json").exists()
    assert (tmp_path / "plots" / "network_cm_xgb_binary.png").stat().st_size > 1000


def test_metrics_are_computed_not_invented(trained: tuple[Path, dict[str, object]]) -> None:
    _, res = trained
    r = res["results"]["rf_binary"]  # type: ignore[index]
    cm = np.array(r["confusion_matrix"]["matrix"])
    tn, fp, fn, tp = cm.ravel()
    assert r["n_test"] == cm.sum()
    assert r["false_positive_rate"] == pytest.approx(fp / (fp + tn))
    assert r["recall"] == pytest.approx(tp / (tp + fn))
    assert r["f1"] > 0.9  # well-separated fake classes: sanity only, never reported as a result
    assert 0 <= r["roc_auc"] <= 1 and 0 <= r["pr_auc"] <= 1


def test_predictor_scores_and_validates(trained: tuple[Path, dict[str, object]]) -> None:
    out, _ = trained
    p = NetworkPredictor(out, "xgb_binary", threshold=0.5)
    feats = p.features
    benign = {f: 0.0 for f in feats}
    attack = {f: 8.0 for f in feats}
    flagged, prob = p.is_attack(attack)
    assert flagged and prob > 0.5
    assert not p.is_attack(benign)[0]
    assert p.is_attack({**attack, "unknown_extra": 1.0})[0]  # extra keys ignored
    with pytest.raises(ValueError, match="required features"):
        p.is_attack({feats[0]: 1.0})
    # hostile values must not crash or poison scoring
    weird = {**benign, feats[0]: float("nan"), feats[1]: float("inf"), feats[2]: "x"}  # type: ignore[dict-item]
    assert 0.0 <= p.attack_probability(weird) <= 1.0
    with pytest.raises(ValueError):
        NetworkPredictor(out, "xgb_binary", threshold=1.5)


def test_multiclass_predictor(trained: tuple[Path, dict[str, object]]) -> None:
    out, _ = trained
    p = NetworkPredictor(out, "xgb_multi")
    label, conf = p.attack_type({f: 4.0 for f in p.features})
    assert label == "DoS Hulk" and conf > 0.5
