"""Figures for the README and writeup, drawn only from measured results files.

    python -m sentinel.eval.plots

Reads results/metrics.json and results/ml/*.json and writes PNGs to results/plots/. A figure whose
source numbers are missing is skipped and named in the output, never filled with placeholder values.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

RESULTS = Path("results")
PLOTS = RESULTS / "plots"


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}


def binary_cm(name: str, matrix: list[list[int]], labels: list[str], path: Path) -> None:
    arr = np.array(matrix, dtype=float)
    norm = arr / np.maximum(arr.sum(axis=1, keepdims=True), 1)
    fig, ax = plt.subplots(figsize=(4.2, 3.8))
    ax.imshow(norm, cmap="Blues", vmin=0, vmax=1)
    ax.set_xticks(range(2), labels)
    ax.set_yticks(range(2), labels)
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{int(arr[i, j]):,}", ha="center", va="center",
                    color="white" if norm[i, j] > 0.5 else "black")  # fmt: skip
    ax.set_xlabel("predicted")
    ax.set_ylabel("true")
    ax.set_title(name, fontsize=10)
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)


def scenario_heatmap(cm: dict[str, Any], path: Path) -> None:
    cols: list[str] = cm["columns"]
    rows: dict[str, dict[str, int]] = cm["rows"]
    names = list(rows)
    data = np.array([[rows[r][c] for c in cols] for r in names], dtype=float)
    fig, ax = plt.subplots(figsize=(10, 6))
    im = ax.imshow(np.log10(data + 1), cmap="viridis", aspect="auto")
    ax.set_xticks(range(len(cols)), cols, rotation=60, ha="right", fontsize=7)
    ax.set_yticks(range(len(names)), names, fontsize=7)
    ax.set_xlabel("rule that alerted (none = no alert)")
    ax.set_ylabel("scenario (true label)")
    ax.set_title("Detections per scenario and rule (log10 colour scale)", fontsize=10)
    fig.colorbar(im, ax=ax, fraction=0.03, label="log10(count + 1)")
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)


def latency_bars(lat: dict[str, Any], path: Path) -> None:
    series = [(k, lat[k]) for k in ("time_to_detect", "pipeline_per_detection", "time_to_respond")
              if k in lat]  # fmt: skip
    labels = [k.replace("_", " ") for k, _ in series]
    x = np.arange(len(series))
    width = 0.27
    fig, ax = plt.subplots(figsize=(8, 4.2))
    bars = (("p50_ms", "#4c78a8"), ("p95_ms", "#f58518"), ("max_ms", "#e45756"))
    for offset, (key, color) in zip((-width, 0.0, width), bars, strict=True):
        vals = [v[key] for _, v in series]
        ax.bar(x + offset, vals, width, label=key.replace("_ms", ""), color=color)
    ax.set_yscale("log")
    ax.set_xticks(x, labels)
    ax.set_ylabel("milliseconds (log scale)")
    ax.set_title("Latency from the measured pipeline run (n in metrics.json)", fontsize=10)
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)


def main() -> int:
    PLOTS.mkdir(parents=True, exist_ok=True)
    metrics = _load(RESULTS / "metrics.json")
    ml = _load(RESULTS / "ml" / "anomaly.json")
    phishing = _load(RESULTS / "ml" / "phishing.json")
    fraud = _load(RESULTS / "ml" / "fraud.json")
    written: list[str] = []
    skipped: list[str] = []

    for model, res in (ml.get("metrics") or {}).items():
        cm = res.get("confusion_matrix")
        if cm:
            out = PLOTS / f"anomaly_cm_{model}.png"
            binary_cm(f"anomaly: {model} (1% FPR)", cm["matrix"], cm["labels"], out)
            written.append(out.name)
    for key in ("deployed_model_without_structure_shortcuts", "full_feature_model"):
        cm = (phishing.get(key) or {}).get("confusion_matrix")
        if cm:
            out = PLOTS / f"phishing_cm_{key}.png"
            binary_cm(f"phishing: {key.replace('_', ' ')}", cm["matrix"], cm["labels"], out)
            written.append(out.name)
    cm = (fraud.get("precision_targets", {}).get("precision_0.80", {}).get("test") or {}).get(
        "confusion_matrix"
    )
    if cm:
        out = PLOTS / "fraud_cm_precision_0.80_test.png"
        binary_cm("card fraud: test, threshold for 0.80 precision", cm["matrix"], cm["labels"], out)
        written.append(out.name)

    pipeline = metrics.get("pipeline", {})
    if pipeline.get("confusion_matrix", {}).get("rows"):
        out = PLOTS / "pipeline_scenario_rule_heatmap.png"
        scenario_heatmap(pipeline["confusion_matrix"], out)
        written.append(out.name)
    else:
        skipped.append(
            "pipeline_scenario_rule_heatmap (no pipeline confusion matrix in metrics.json)"
        )
    if pipeline.get("latency"):
        out = PLOTS / "latency.png"
        latency_bars(pipeline["latency"], out)
        written.append(out.name)
    else:
        skipped.append("latency.png (no latency section in metrics.json)")

    print("wrote:", ", ".join(written) if written else "nothing")
    for s in skipped:
        print("skipped:", s, file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
