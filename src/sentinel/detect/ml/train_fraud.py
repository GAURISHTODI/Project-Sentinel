"""Train the card-fraud model: python -m sentinel.detect.ml.train_fraud

Data: the ULB credit-card fraud dataset (Dal Pozzolo et al., 2015; 284,807 transactions,
492 frauds), read from a Hugging Face re-upload whose row and fraud counts match the published
dataset. Features V1..V28 are anonymised PCA components, plus Time and Amount.

Order (tested): stratified split into train and test -> stratified split of train into fit and
validation -> class weights from the fit split only -> XGBoost fit on the fit split -> alert
thresholds chosen on the VALIDATION split for several precision targets -> evaluation on the
untouched test split.
No imbalance resampling is used, so nothing synthetic enters the training data.
"""

from __future__ import annotations

import argparse
import json
import platform
import time
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, precision_recall_curve, roc_auc_score
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

DEFAULT_CSV = Path("data/fraud/creditcard.csv")
DEFAULT_OUT = Path("models/fraud")
RESULTS = Path("results/ml")
FEATURES = ["Time", *[f"V{i}" for i in range(1, 29)], "Amount"]
PRECISION_TARGETS = (0.5, 0.8, 0.9)
DATASET = (
    "ULB credit-card fraud (Dal Pozzolo et al. 2015), "
    "Hugging Face re-upload David-Egea/Creditcard-fraud-detection"
)


def load_csv(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, dtype={c: np.float32 for c in FEATURES})
    out = df[FEATURES].astype(np.float32)
    out["Class"] = df["Class"].astype(int)
    return out


def pick_threshold(y: np.ndarray, prob: np.ndarray, target_precision: float) -> float | None:
    """Smallest threshold whose validation precision meets the target (max recall), or None."""
    precision, _recall, thresholds = precision_recall_curve(y, prob)
    ok = np.where(precision[:-1] >= target_precision)[0]
    if len(ok) == 0:
        return None
    return float(thresholds[ok[0]])


def at_threshold(y: np.ndarray, prob: np.ndarray, thr: float | None) -> dict[str, Any]:
    if thr is None:
        return {"threshold": None, "reachable": False}
    pred = prob >= thr
    tp = int(np.sum(pred & (y == 1)))
    fp = int(np.sum(pred & (y == 0)))
    fn = int(np.sum(~pred & (y == 1)))
    tn = int(np.sum(~pred & (y == 0)))
    return {
        "threshold": thr,
        "reachable": True,
        "precision": float(tp / max(tp + fp, 1)),
        "recall": float(tp / max(tp + fn, 1)),
        "false_positive_rate": float(fp / max(fp + tn, 1)),
        "confusion_matrix": {"labels": ["legitimate", "fraud"], "matrix": [[tn, fp], [fn, tp]]},
    }


def train(
    df: pd.DataFrame, out_dir: Path, results_dir: Path | None, seed: int = 42
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    X = df[FEATURES]
    y = df["Class"].to_numpy()
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, stratify=y, random_state=seed)
    X_fit, X_val, y_fit, y_val = train_test_split(
        X_tr, y_tr, test_size=0.2, stratify=y_tr, random_state=seed
    )
    neg, pos = int(np.sum(y_fit == 0)), int(np.sum(y_fit == 1))
    model = XGBClassifier(
        n_estimators=300, max_depth=5, learning_rate=0.1, tree_method="hist",
        scale_pos_weight=neg / pos, eval_metric="aucpr", n_jobs=-1, random_state=seed,
    )  # fmt: skip
    model.fit(X_fit, y_fit)

    val_prob = model.predict_proba(X_val)[:, 1]
    test_prob = model.predict_proba(X_te)[:, 1]
    targets: dict[str, Any] = {}
    for target in PRECISION_TARGETS:
        thr = pick_threshold(y_val, val_prob, target)
        targets[f"precision_{target:.2f}"] = {
            "chosen_on": "validation split",
            "validation": at_threshold(y_val, val_prob, thr),
            "test": at_threshold(y_te, test_prob, thr),
        }
    deployed = pick_threshold(y_val, val_prob, 0.8)
    result: dict[str, Any] = {
        "test_pr_auc": float(average_precision_score(y_te, test_prob)),
        "test_roc_auc": float(roc_auc_score(y_te, test_prob)),
        "test_prevalence": float(np.mean(y_te)),
        "test_n": int(len(y_te)),
        "test_fraud": int(np.sum(y_te)),
        "precision_targets": targets,
        "deployed_threshold": deployed,
        "deployed_threshold_target_precision": 0.8,
    }
    train_seconds = round(time.time() - t0, 1)

    joblib.dump(
        {"model": model, "features": FEATURES, "threshold": deployed, "target_precision": 0.8},
        out_dir / "fraud_model.joblib", compress=3,
    )  # fmt: skip
    card: dict[str, Any] = {
        "model": "card-fraud-xgboost",
        "dataset": DATASET,
        "rows": int(len(df)),
        "frauds": int(np.sum(y)),
        "split": {
            "method": "stratified 80/20 train/test, then stratified 80/20 fit/validation of train",
            "fit_rows": int(len(X_fit)),
            "validation_rows": int(len(X_val)),
            "test_rows": int(len(X_te)),
            "seed": seed,
        },
        "imbalance": f"scale_pos_weight = {neg}/{pos} from fit split; no resampling",
        "model_params": {"type": "XGBoost", "n_estimators": 300, "max_depth": 5, "lr": 0.1},
        "metrics": result,
        "train_seconds": train_seconds,
        "environment": {"python": platform.python_version(), "platform": platform.platform()},
        "limitations": [
            "V1..V28 are anonymised PCA components; decisions cannot be explained in business",
            "The dataset is from two days in September 2013 with European cardholders only.",
            "Time is seconds from the first dataset transaction, not wall-clock time",
            "Thresholds were chosen on validation rows for a precision target; live rates differ",
        ],
    }
    (out_dir / "model_card.json").write_text(json.dumps(card, indent=2), encoding="utf-8")
    if results_dir is not None:
        results_dir.mkdir(parents=True, exist_ok=True)
        (results_dir / "fraud.json").write_text(
            json.dumps({"dataset": DATASET, **result, "split": card["split"],
                        "imbalance": card["imbalance"], "limitations": card["limitations"]},
                       indent=2),
            encoding="utf-8",
        )  # fmt: skip
    return {"card": card, "result": result}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Train Sentinel's card-fraud model")
    ap.add_argument("--csv", type=Path, default=DEFAULT_CSV)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args(argv)
    df = load_csv(a.csv)
    print(f"rows={len(df):,} frauds={int(df['Class'].sum()):,}")
    r = train(df, a.out, RESULTS, a.seed)["result"]
    print(f"test PR-AUC={r['test_pr_auc']:.4f} ROC-AUC={r['test_roc_auc']:.4f} "
          f"prevalence={r['test_prevalence']:.5f} "
          f"(test n={r['test_n']:,}, fraud={r['test_fraud']})")  # fmt: skip
    for key, t in r["precision_targets"].items():
        te = t["test"]
        if te["reachable"]:
            print(f"{key}: test precision={te['precision']:.4f} recall={te['recall']:.4f} "
                  f"FPR={te['false_positive_rate']:.5f} "
                  f"threshold={te['threshold']:.4f}")  # fmt: skip
        else:
            print(f"{key}: not reachable on validation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
