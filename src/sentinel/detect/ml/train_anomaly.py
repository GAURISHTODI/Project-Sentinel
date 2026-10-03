"""Train unsupervised anomaly detectors on benign traffic only.

    python -m sentinel.detect.ml.train_anomaly --sample 200000

Order (tested): stratified split (same as the supervised model) -> benign TRAIN rows split into a
fit set and a validation set -> scaler, Isolation Forest and autoencoder fit on the fit set only ->
threshold chosen on benign validation rows for a target false-positive rate -> evaluation on the
untouched test split. Attack labels are never used to fit or to pick a threshold.
Results are written to results/ml/anomaly.json, separate from the supervised models.
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
import torch
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from torch import nn

from sentinel.detect.ml.data import BENIGN, LoadReport, load_cicids
from sentinel.detect.ml.train_network import DEFAULT_SOURCE, split_data

DEFAULT_DATA = Path("archive")
DEFAULT_OUT = Path("models/anomaly")
RESULTS = Path("results/ml")
TARGET_FPR = 0.01
VAL_FRACTION = 0.25
BATCH = 512
LEARNING_RATE = 1e-3


class AutoEncoder(nn.Module):
    def __init__(self, n_in: int) -> None:
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(n_in, 32), nn.ReLU(),
            nn.Linear(32, 8), nn.ReLU(),
            nn.Linear(8, 32), nn.ReLU(),
            nn.Linear(32, n_in),
        )  # fmt: skip

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x)  # type: ignore[no-any-return]


def benign_fit_and_val(
    X: pd.DataFrame, y: pd.Series, seed: int
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Split the benign rows of a training split into a fit set and a threshold-validation set."""
    benign = X[y == BENIGN]
    fit, val = train_test_split(benign, test_size=VAL_FRACTION, random_state=seed)
    return fit, val


def pick_threshold(benign_val_scores: np.ndarray, target_fpr: float) -> float:
    """Alert threshold so that about `target_fpr` of benign validation traffic exceeds it."""
    return float(np.quantile(benign_val_scores, 1.0 - target_fpr))


def train_autoencoder(X: np.ndarray, seed: int, epochs: int) -> AutoEncoder:
    torch.manual_seed(seed)
    model = AutoEncoder(X.shape[1])
    optim = torch.optim.Adam(model.parameters(), lr=LEARNING_RATE)
    data = torch.from_numpy(X.astype(np.float32))
    model.train()
    for _ in range(epochs):
        perm = torch.randperm(len(data))
        for start in range(0, len(data), BATCH):
            batch = data[perm[start : start + BATCH]]
            loss = nn.functional.mse_loss(model(batch), batch)
            optim.zero_grad()
            loss.backward()  # type: ignore[no-untyped-call]
            optim.step()
    model.eval()
    return model


def autoencoder_scores(model: AutoEncoder, X: np.ndarray) -> np.ndarray:
    with torch.no_grad():
        t = torch.from_numpy(X.astype(np.float32))
        return ((model(t) - t) ** 2).mean(dim=1).numpy()  # type: ignore[no-any-return]


def evaluate(
    scores: np.ndarray, threshold: float, y_attack: np.ndarray, labels: np.ndarray
) -> dict[str, Any]:
    pred = scores > threshold
    attack = y_attack == 1
    tp = int(np.sum(pred & attack))
    fp = int(np.sum(pred & ~attack))
    fn = int(np.sum(~pred & attack))
    tn = int(np.sum(~pred & ~attack))
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    per_class = {
        str(c): float(np.mean(pred[labels == c])) for c in sorted(set(labels)) if c != BENIGN
    }
    return {
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(2 * precision * recall / max(precision + recall, 1e-12)),
        "false_positive_rate": float(fp / max(fp + tn, 1)),
        "roc_auc": float(roc_auc_score(y_attack, scores)),
        "pr_auc": float(average_precision_score(y_attack, scores)),
        "threshold": float(threshold),
        "threshold_policy": f"{TARGET_FPR:.0%} FPR on held-out benign validation rows",
        "detection_rate_by_class": per_class,
        "confusion_matrix": {"labels": ["benign", "attack"], "matrix": [[tn, fp], [fn, tp]]},
        "n_test": int(len(y_attack)),
        "n_test_attack": int(attack.sum()),
    }


def train(
    df: pd.DataFrame,
    report: LoadReport | None,
    out_dir: Path,
    results_dir: Path | None = None,
    seed: int = 42,
    epochs: int = 15,
    dataset_source: str = DEFAULT_SOURCE,
) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    X_tr, X_te, y_tr, y_te = split_data(df, seed)
    features = list(X_tr.columns)
    fit_raw, val_raw = benign_fit_and_val(X_tr, y_tr, seed)

    scaler = StandardScaler().fit(fit_raw)
    fit_s, val_s = scaler.transform(fit_raw), scaler.transform(val_raw)
    test_s = scaler.transform(X_te)
    y_attack = (y_te != BENIGN).to_numpy().astype(int)
    labels = y_te.to_numpy()

    t0 = time.time()
    forest = IsolationForest(n_estimators=200, random_state=seed, n_jobs=-1).fit(fit_s)
    forest_val = -forest.score_samples(val_s)
    forest_thr = pick_threshold(forest_val, TARGET_FPR)
    forest_scores = -forest.score_samples(test_s)

    ae = train_autoencoder(fit_s, seed, epochs)
    ae_val = autoencoder_scores(ae, val_s)
    ae_thr = pick_threshold(ae_val, TARGET_FPR)
    ae_scores = autoencoder_scores(ae, test_s)
    train_seconds = round(time.time() - t0, 1)

    results = {
        "isolation_forest": evaluate(forest_scores, forest_thr, y_attack, labels),
        "autoencoder": evaluate(ae_scores, ae_thr, y_attack, labels),
    }

    joblib.dump(
        {"model": forest, "scaler": scaler, "threshold": forest_thr, "features": features},
        out_dir / "isolation_forest.joblib",
        compress=3,
    )
    joblib.dump(
        {
            "state_dict": {k: v.cpu() for k, v in ae.state_dict().items()},
            "n_in": len(features),
            "scaler": scaler,
            "threshold": ae_thr,
            "features": features,
        },
        out_dir / "autoencoder.joblib",
        compress=3,
    )

    card: dict[str, Any] = {
        "model": "network-anomaly",
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "training_data": "benign rows only; attack labels never fit or pick a threshold",
        "dataset": {
            "name": "CIC-IDS2017 MachineLearningCVE",
            "source": dataset_source,
            "load_report": asdict(report) if report else None,
        },
        "seed": seed,
        "split": {
            "test_size": 0.2,
            "train_rows": int(len(X_tr)),
            "benign_fit_rows": int(len(fit_raw)),
            "benign_validation_rows": int(len(val_raw)),
            "test_rows": int(len(X_te)),
            "test_attack_rows": int(y_attack.sum()),
            "scaler_fit_on": "benign fit rows only",
        },
        "models": {
            "isolation_forest": {"type": "IsolationForest", "trees": 200},
            "autoencoder": {
                "type": "PyTorch MLP autoencoder",
                "architecture": f"{len(features)}-32-8-32-{len(features)}",
                "epochs": epochs,
                "loss": "mean squared reconstruction error",
            },
        },
        "features": features,
        "metrics": results,
        "train_seconds": train_seconds,
        "environment": {
            "python": platform.python_version(),
            "torch": torch.__version__,
            "platform": platform.platform(),
        },
        "limitations": [
            "Benign traffic from one simulated CIC-IDS2017 network; real benign traffic differs.",
            "Scores are not calibrated probabilities; the threshold targets an FPR, not precision.",
            "Attacks that look statistically normal are expected to be missed.",
            "Reported separately from the supervised models; not directly comparable.",
        ],
    }  # fmt: skip
    (out_dir / "model_card.json").write_text(json.dumps(card, indent=2), encoding="utf-8")
    if results_dir is not None:
        results_dir.mkdir(parents=True, exist_ok=True)
        (results_dir / "anomaly.json").write_text(
            json.dumps({"training_data": card["training_data"], "split": card["split"],
                        "models": card["models"], "metrics": results,
                        "limitations": card["limitations"]}, indent=2),
            encoding="utf-8",
        )  # fmt: skip
    return {"card": card, "results": results}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Train Sentinel's unsupervised anomaly detectors")
    ap.add_argument("--data-dir", type=Path, default=DEFAULT_DATA)
    ap.add_argument("--sample", type=int, default=200_000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--epochs", type=int, default=15)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    a = ap.parse_args(argv)

    df, rep = load_cicids(a.data_dir, a.sample, a.seed)
    print(f"sampled {len(df):,} rows; labels {rep.sample_label_counts}")
    out = train(df, rep, a.out, RESULTS, a.seed, a.epochs)
    for name, r in out["results"].items():
        print(
            f"\n=== {name} (benign-only training) ===  recall={r['recall']:.4f} "
            f"precision={r['precision']:.4f} FPR={r['false_positive_rate']:.4f} "
            f"ROC-AUC={r['roc_auc']:.4f} PR-AUC={r['pr_auc']:.4f}"
        )
        for cls, rate in r["detection_rate_by_class"].items():
            print(f"  detection rate {cls:28s}{rate:.4f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
