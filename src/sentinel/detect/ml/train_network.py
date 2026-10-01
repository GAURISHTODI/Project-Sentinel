"""Train the supervised network IDS: python -m sentinel.detect.ml.train_network --sample 200000.

Order matters (and is tested): clean/deduplicate -> sample -> SPLIT -> fit scaler on train only
-> train -> evaluate on the untouched test split. Nothing here tunes on the test set.
"""

from __future__ import annotations

import argparse
import json
import platform
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    average_precision_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder, StandardScaler
from xgboost import XGBClassifier

from sentinel.detect.ml.data import BENIGN, LABEL, LoadReport, load_cicids

DEFAULT_DATA = Path("archive")
DEFAULT_OUT = Path("models/network")
RESULTS = Path("results/ml")
PLOTS = Path("results/plots")


def split_data(
    df: pd.DataFrame, seed: int = 42, test_size: float = 0.2
) -> tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series]:
    """Stratified train/test split on the class label. Done BEFORE any scaling."""
    X = df.drop(columns=[LABEL])
    y = df[LABEL]
    return train_test_split(X, y, test_size=test_size, random_state=seed, stratify=y)  # type: ignore[no-any-return]


def make_pipeline(kind: str, seed: int, trees: int, n_jobs: int) -> Pipeline:
    if kind == "rf":
        clf: Any = RandomForestClassifier(
            n_estimators=trees, min_samples_leaf=2, n_jobs=n_jobs, random_state=seed
        )
    else:
        clf = XGBClassifier(
            n_estimators=trees, max_depth=8, learning_rate=0.1, tree_method="hist",
            n_jobs=n_jobs, random_state=seed, eval_metric="logloss",
        )  # fmt: skip
    return Pipeline([("scale", StandardScaler()), ("clf", clf)])


def eval_binary(pipe: Pipeline, X: pd.DataFrame, y_attack: np.ndarray[Any, Any]) -> dict[str, Any]:
    prob = pipe.predict_proba(X)[:, 1]
    pred = (prob >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_attack, pred, labels=[0, 1]).ravel()
    rep = classification_report(y_attack, pred, target_names=["benign", "attack"], output_dict=True)
    return {
        "precision": float(tp / max(tp + fp, 1)),
        "recall": float(tp / max(tp + fn, 1)),
        "f1": float(rep["attack"]["f1-score"]),
        "false_positive_rate": float(fp / max(fp + tn, 1)),
        "false_negative_rate": float(fn / max(fn + tp, 1)),
        "roc_auc": float(roc_auc_score(y_attack, prob)),
        "pr_auc": float(average_precision_score(y_attack, prob)),
        "confusion_matrix": {"labels": ["benign", "attack"], "matrix": [[int(tn), int(fp)], [int(fn), int(tp)]]},
        "threshold": 0.5,
        "n_test": int(len(y_attack)),
        "report": rep,
    }  # fmt: skip


def eval_multi(pipe: Pipeline, X: pd.DataFrame, y_enc: np.ndarray[Any, Any], classes: list[str]) -> dict[str, Any]:
    pred = pipe.predict(X)
    labels = list(range(len(classes)))
    rep = classification_report(
        y_enc, pred, labels=labels, target_names=classes, output_dict=True, zero_division=0
    )
    cm = confusion_matrix(y_enc, pred, labels=labels)
    return {
        "macro_f1": float(rep["macro avg"]["f1-score"]),
        "weighted_f1": float(rep["weighted avg"]["f1-score"]),
        "accuracy": float(rep["accuracy"]),
        "per_class": {c: {k: float(v) for k, v in rep[c].items()} for c in classes},
        "confusion_matrix": {"labels": classes, "matrix": cm.tolist()},
        "n_test": int(len(y_enc)),
    }  # fmt: skip


def _plot_cm(cm: list[list[int]], labels: list[str], title: str, path: Path) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    arr = np.array(cm, dtype=float)
    norm = arr / np.maximum(arr.sum(axis=1, keepdims=True), 1)
    size = max(4, 0.55 * len(labels) + 2)
    fig, ax = plt.subplots(figsize=(size, size * 0.9))
    ax.imshow(norm, cmap="Blues", vmin=0, vmax=1)
    ax.set_xticks(range(len(labels)), labels, rotation=60, ha="right", fontsize=7)
    ax.set_yticks(range(len(labels)), labels, fontsize=7)
    for i in range(len(labels)):
        for j in range(len(labels)):
            if arr[i, j]:
                ax.text(j, i, int(arr[i, j]), ha="center", va="center", fontsize=6,
                        color="white" if norm[i, j] > 0.5 else "black")  # fmt: skip
    ax.set_xlabel("predicted")
    ax.set_ylabel("true")
    ax.set_title(title, fontsize=9)
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=130)
    plt.close(fig)


def _print_cm(name: str, ev: dict[str, Any]) -> None:
    cm = ev["confusion_matrix"]
    print(f"\n{name} confusion matrix (rows=true, cols=predicted) labels={cm['labels']}")
    for lab, row in zip(cm["labels"], cm["matrix"], strict=True):
        print(f"  {lab:28s}{row}")


def train(
    df: pd.DataFrame,
    report: LoadReport | None,
    out_dir: Path,
    results_dir: Path | None = None,
    plots_dir: Path | None = None,
    seed: int = 42,
    rf_trees: int = 100,
    xgb_trees: int = 200,
    n_jobs: int = -1,
    mlflow_uri: str | None = None,
    dataset_source: str = "unspecified (pass --dataset-source)",
    min_multi_support: int = 20,
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    X_tr, X_te, y_tr, y_te = split_data(df, seed)
    features = list(X_tr.columns)
    ya_tr = (y_tr != BENIGN).astype(int).to_numpy()
    ya_te = (y_te != BENIGN).astype(int).to_numpy()

    # multi-class: only classes with enough TRAIN rows to learn from; the rest are reported, not hidden
    support = y_tr.value_counts()
    kept = sorted(c for c in support.index if support[c] >= min_multi_support)
    skipped = {str(c): int(support[c]) for c in support.index if c not in kept}
    enc = LabelEncoder().fit(kept)
    m_tr = y_tr.isin(kept).to_numpy()
    m_te = y_te.isin(kept).to_numpy()

    results: dict[str, Any] = {}
    fitted: dict[str, Pipeline] = {}
    t0 = time.time()
    for name, kind, trees in (("rf_binary", "rf", rf_trees), ("xgb_binary", "xgb", xgb_trees)):
        pipe = make_pipeline(kind, seed, trees, n_jobs).fit(X_tr, ya_tr)
        fitted[name] = pipe
        results[name] = eval_binary(pipe, X_te, ya_te)
    multi = make_pipeline("xgb", seed, xgb_trees, n_jobs)
    multi.set_params(clf__objective="multi:softprob", clf__eval_metric="mlogloss")
    multi.fit(X_tr[m_tr], enc.transform(y_tr[m_tr]))
    fitted["xgb_multi"] = multi
    results["xgb_multi"] = eval_multi(
        multi, X_te[m_te], enc.transform(y_te[m_te]), [str(c) for c in enc.classes_]
    )
    results["xgb_multi"]["classes_not_trained"] = skipped
    train_seconds = round(time.time() - t0, 1)

    for name, pipe in fitted.items():
        joblib.dump(
            {"pipeline": pipe, "features": features,
             "classes": [str(c) for c in enc.classes_] if name == "xgb_multi" else ["benign", "attack"]},
            out_dir / f"{name}.joblib", compress=3,
        )  # fmt: skip

    card: dict[str, Any] = {
        "model": "network-ids",
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "dataset": {
            "name": "CIC-IDS2017 MachineLearningCVE",
            "source": dataset_source,
            "load_report": asdict(report) if report else None,
        },
        "sample_size": int(len(df)),
        "seed": seed,
        "split": {
            "test_size": 0.2, "stratified_on": "class label", "train_rows": int(len(X_tr)),
            "test_rows": int(len(X_te)), "scaler_fit_on": "train split only",
            "train_label_counts": {str(k): int(v) for k, v in y_tr.value_counts().items()},
            "test_label_counts": {str(k): int(v) for k, v in y_te.value_counts().items()},
        },  # fmt: skip
        "features": features,
        "models": {
            "rf_binary": {"type": "RandomForest", "trees": rf_trees},
            "xgb_binary": {"type": "XGBoost", "trees": xgb_trees, "max_depth": 8},
            "xgb_multi": {"type": "XGBoost multi-class", "classes": [str(c) for c in enc.classes_]},
        },
        "metrics": {k: {m: v for m, v in r.items() if m != "report"} for k, r in results.items()},
        "train_seconds": train_seconds,
        "environment": {"python": platform.python_version(), "platform": platform.platform()},
        "limitations": [
            "CIC-IDS2017 is a curated lab capture from 2017; real-world traffic will differ.",
            "Rare attack classes have very few test rows; their per-class scores are noisy.",
            "Per-class floor (min_per_class) slightly over-represents the rarest classes.",
            "Destination Port is a feature and can act as a shortcut for some attack types.",
        ],
    }
    (out_dir / "model_card.json").write_text(json.dumps(card, indent=2), encoding="utf-8")
    if results_dir is not None:
        results_dir.mkdir(parents=True, exist_ok=True)
        (results_dir / "network.json").write_text(json.dumps(card["metrics"], indent=2), encoding="utf-8")
    if plots_dir is not None:
        for name in ("rf_binary", "xgb_binary", "xgb_multi"):
            cm = results[name]["confusion_matrix"]
            _plot_cm(cm["matrix"], cm["labels"], name, plots_dir / f"network_cm_{name}.png")
    if mlflow_uri:
        _log_mlflow(mlflow_uri, card, results, out_dir, seed)
    return {"card": card, "results": results}


def _log_mlflow(uri: str, card: dict[str, Any], results: dict[str, Any], out_dir: Path, seed: int) -> None:
    import mlflow

    mlflow.set_tracking_uri(uri)
    mlflow.set_experiment("sentinel-network-ids")
    for name, res in results.items():
        with mlflow.start_run(run_name=name):
            mlflow.log_params({"model": name, "seed": seed, "sample_size": card["sample_size"],
                               **{k: v for k, v in card["models"][name].items() if k != "classes"}})  # fmt: skip
            mlflow.log_metrics({k: v for k, v in res.items() if isinstance(v, float)})
            mlflow.log_artifact(str(out_dir / "model_card.json"))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Train Sentinel's supervised network IDS")
    ap.add_argument("--data-dir", type=Path, default=DEFAULT_DATA)
    ap.add_argument("--sample", type=int, default=200_000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--rf-trees", type=int, default=100)
    ap.add_argument("--xgb-trees", type=int, default=200)
    ap.add_argument("--dataset-source", default="unspecified (pass --dataset-source)")
    ap.add_argument("--no-mlflow", action="store_true")
    a = ap.parse_args(argv)

    t0 = time.time()
    df, rep = load_cicids(a.data_dir, a.sample, a.seed)
    print(f"loaded {rep.raw_rows:,} raw rows -> {len(df):,} sampled in {time.time() - t0:.0f}s; "
          f"dropped {rep.dropped_non_finite:,} non-finite, {rep.dropped_duplicates:,} duplicates, "
          f"columns {rep.dropped_columns}")  # fmt: skip
    print("sample class counts:", rep.sample_label_counts)
    out = train(
        df, rep, a.out, RESULTS, PLOTS, a.seed, a.rf_trees, a.xgb_trees,
        mlflow_uri=None if a.no_mlflow else "sqlite:///mlflow.db",
        dataset_source=a.dataset_source,
    )  # fmt: skip
    for name in ("rf_binary", "xgb_binary"):
        r = out["results"][name]
        print(f"\n=== {name} ===  F1={r['f1']:.4f} precision={r['precision']:.4f} recall={r['recall']:.4f} "
              f"FPR={r['false_positive_rate']:.4f} ROC-AUC={r['roc_auc']:.4f} PR-AUC={r['pr_auc']:.4f}")  # fmt: skip
        _print_cm(name, r)
    m = out["results"]["xgb_multi"]
    print(f"\n=== xgb_multi ===  macro-F1={m['macro_f1']:.4f} weighted-F1={m['weighted_f1']:.4f} accuracy={m['accuracy']:.4f}")
    print(f"{'class':28s}{'precision':>10s}{'recall':>8s}{'f1':>8s}{'support':>9s}")
    for cls, s in m["per_class"].items():
        print(f"{cls:28s}{s['precision']:10.3f}{s['recall']:8.3f}{s['f1-score']:8.3f}{int(s['support']):9d}")
    if m["classes_not_trained"]:
        print("classes with too few training rows, not in the multi-class model:", m["classes_not_trained"])
    print(f"\nmodel card: {a.out / 'model_card.json'}   total {time.time() - t0:.0f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
