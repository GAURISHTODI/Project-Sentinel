"""Train the phishing URL classifier: python -m sentinel.detect.ml.train_phishing

Data: PhiUSIIL Phishing URL Dataset (UCI id 967). Label 1 = legitimate, 0 = phishing,
confirmed on the UCI page. Only the URL string is used. The dataset's page-content columns
are not available for a URL seen in live traffic, so they are excluded.

Order (tested): dedupe on URL -> split by host so no domain is in both train and test ->
features from the URL string -> XGBoost fit on train only -> evaluate on the untouched test
split at a fixed 0.5 threshold. Nothing is tuned on the test split.
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
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import GroupShuffleSplit
from xgboost import XGBClassifier

from sentinel.detect.ml.url_features import FEATURE_NAMES, host_of, url_features

DEFAULT_CSV = Path("data/phishing/PhiUSIIL_Phishing_URL_Dataset.csv")
DEFAULT_OUT = Path("models/phishing")
RESULTS = Path("results/ml")
DATASET = "PhiUSIIL Phishing URL Dataset (UCI id 967, 2024)"
THRESHOLD = 0.5
# Found by inspecting feature importances: the full model leans on these structural shortcuts.
SHORTCUT_FEATURES = ["path_len", "has_https", "has_www"]
PROBE_ROWS = 5000


def load(csv: Path) -> tuple[pd.DataFrame, dict[str, int]]:
    raw = pd.read_csv(csv, usecols=["URL", "label"], encoding="utf-8-sig")
    counts = {"rows": len(raw)}
    df = raw.drop_duplicates(subset="URL", keep="first").reset_index(drop=True)
    counts["duplicate_urls_dropped"] = len(raw) - len(df)
    df["phishing"] = (df["label"] == 0).astype(int)
    return df, counts


def featurize(urls: pd.Series) -> pd.DataFrame:
    return pd.DataFrame([url_features(u) for u in urls], columns=FEATURE_NAMES)


def group_split(df: pd.DataFrame, seed: int) -> tuple[np.ndarray, np.ndarray]:
    hosts = df["URL"].map(host_of).to_numpy()
    tr, te = next(
        GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=seed).split(df, groups=hosts)
    )
    overlap = set(hosts[tr]) & set(hosts[te])
    if overlap:
        raise RuntimeError("host overlap between train and test")
    return tr, te


def make_model(seed: int) -> XGBClassifier:
    return XGBClassifier(
        n_estimators=300, max_depth=6, learning_rate=0.1, tree_method="hist",
        n_jobs=-1, random_state=seed, eval_metric="logloss",
    )  # fmt: skip


def evaluate(prob: np.ndarray, y: np.ndarray) -> dict[str, Any]:
    pred = (prob >= THRESHOLD).astype(int)
    tp = int(np.sum((pred == 1) & (y == 1)))
    fp = int(np.sum((pred == 1) & (y == 0)))
    fn = int(np.sum((pred == 0) & (y == 1)))
    tn = int(np.sum((pred == 0) & (y == 0)))
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    return {
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(2 * precision * recall / max(precision + recall, 1e-12)),
        "false_positive_rate": float(fp / max(fp + tn, 1)),
        "roc_auc": float(roc_auc_score(y, prob)),
        "pr_auc": float(average_precision_score(y, prob)),
        "threshold": THRESHOLD,
        "confusion_matrix": {"labels": ["legitimate", "phishing"], "matrix": [[tn, fp], [fn, tp]]},
        "n_test": int(len(y)),
        "n_test_phishing": int(y.sum()),
    }


def train(df: pd.DataFrame, counts: dict[str, int], out_dir: Path, results_dir: Path | None,
          seed: int = 42) -> dict[str, Any]:  # fmt: skip
    out_dir.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    X = featurize(df["URL"])
    y = df["phishing"].to_numpy()
    tr, te = group_split(df, seed)
    kept = [f for f in FEATURE_NAMES if f not in SHORTCUT_FEATURES]
    full = make_model(seed).fit(X.iloc[tr], y[tr])
    robust = make_model(seed).fit(X.iloc[tr][kept], y[tr])
    legit_te = df.iloc[te][df["phishing"].iloc[te].to_numpy() == 0]
    probe = legit_te["URL"].head(PROBE_ROWS).map(lambda u: u.rstrip("/") + "/")
    probe_X = featurize(probe)
    full_result = evaluate(full.predict_proba(X.iloc[te])[:, 1], y[te])
    robust_result = evaluate(robust.predict_proba(X.iloc[te][kept])[:, 1], y[te])
    full_result["trailing_slash_false_positive_rate"] = float(
        np.mean(full.predict_proba(probe_X)[:, 1] >= THRESHOLD)
    )
    robust_result["trailing_slash_false_positive_rate"] = float(
        np.mean(robust.predict_proba(probe_X[kept])[:, 1] >= THRESHOLD)
    )
    result = {
        "deployed_model_without_structure_shortcuts": robust_result,
        "full_feature_model": full_result,
    }
    train_seconds = round(time.time() - t0, 1)

    joblib.dump({"model": robust, "features": kept}, out_dir / "url_model.joblib", compress=3)
    joblib.dump(
        {"model": full, "features": FEATURE_NAMES}, out_dir / "url_model_full.joblib", compress=3
    )
    card: dict[str, Any] = {
        "model": "phishing-url",
        "dataset": DATASET,
        "features": "URL string only (lexical); page-content columns excluded",
        "dedupe": counts,
        "split": {
            "method": "group split by hostname (no host in both train and test)",
            "train_rows": int(len(tr)),
            "test_rows": int(len(te)),
            "seed": seed,
        },
        "model_params": {"type": "XGBoost", "n_estimators": 300, "max_depth": 6},
        "deployed": "deployed_model_without_structure_shortcuts",
        "deployment_note": (
            "Both models flag legitimate URLs once a trailing slash is added (see "
            "trailing_slash_false_positive_rate). The dataset has no legitimate URL with a path, "
            "so the models learn that a bare domain means legitimate. The detector is therefore "
            "opt-in (PHISHING_DETECTOR_ENABLED) and must not be treated as a production phishing "
            "control. The deployed model was switched to the one without path_len, has_https and "
            "has_www after the full model's trailing-slash failure was seen on live URLs."
        ),
        "metrics": result,
        "train_seconds": train_seconds,
        "environment": {"python": platform.python_version(), "platform": platform.platform()},
        "limitations": [
            "Lexical features only: a well-made phishing URL on a clean-looking domain can pass.",
            "Dataset is a 2024 snapshot; phishing kits and naming habits drift over time.",
            "Threshold fixed at 0.5 and not calibrated for live traffic base rates.",
            "The URL string is untrusted; features are length-capped before parsing.",
        ],
    }
    (out_dir / "model_card.json").write_text(json.dumps(card, indent=2), encoding="utf-8")
    if results_dir is not None:
        results_dir.mkdir(parents=True, exist_ok=True)
        (results_dir / "phishing.json").write_text(json.dumps(card["metrics"] | {
            "dataset": DATASET, "split": card["split"], "dedupe": counts,
            "features": card["features"], "limitations": card["limitations"],
        }, indent=2), encoding="utf-8")  # fmt: skip
    return {"card": card, "result": result}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Train Sentinel's phishing URL classifier")
    ap.add_argument("--csv", type=Path, default=DEFAULT_CSV)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args(argv)
    df, counts = load(a.csv)
    print(f"rows={counts['rows']:,} duplicate URLs dropped={counts['duplicate_urls_dropped']:,}")
    res = train(df, counts, a.out, RESULTS, a.seed)["result"]
    for name, r in res.items():
        print(
            f"{name}: precision={r['precision']:.4f} recall={r['recall']:.4f} F1={r['f1']:.4f} "
            f"FPR={r['false_positive_rate']:.4f} ROC-AUC={r['roc_auc']:.4f} "
            f"PR-AUC={r['pr_auc']:.4f} "
            f"trailing-slash FPR={r['trailing_slash_false_positive_rate']:.4f}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
