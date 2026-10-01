"""CIC-IDS2017 (MachineLearningCVE) loader: file by file, float32, cleaned, stratified sample.

Memory plan for a 16 GB laptop: one CSV is in memory at a time; each is down-sampled right after
cleaning, so the 2.8M-row corpus never exists in full as a DataFrame.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd

LABEL = "Label"
BENIGN = "BENIGN"
_WEB = {"brute force": "Web Attack Brute Force", "xss": "Web Attack XSS",
        "sql injection": "Web Attack SQL Injection"}  # fmt: skip


def normalize_label(raw: str) -> str:
    """Strip whitespace and repair the mojibake in 'Web Attack <garbage> XSS' style labels."""
    s = re.sub(r"\s+", " ", raw.strip())
    if s.lower().startswith("web attack"):
        for key, clean in _WEB.items():
            if key in s.lower():
                return clean
    return s


@dataclass
class LoadReport:
    """What the loader did, for the model card. Every number here is measured, not assumed."""

    files: list[str] = field(default_factory=list)
    raw_rows: int = 0
    raw_label_counts: dict[str, int] = field(default_factory=dict)
    dropped_non_finite: int = 0
    dropped_duplicates: int = 0
    dropped_columns: list[str] = field(default_factory=list)
    sample_label_counts: dict[str, int] = field(default_factory=dict)
    sample_rows: int = 0
    min_per_class: int = 0
    seed: int = 42


def _csv_files(data_dir: Path) -> list[Path]:
    files = sorted(p for p in data_dir.glob("*.csv"))
    if not files:
        raise FileNotFoundError(f"no CSV files in {data_dir}")
    return files


def _read(path: Path) -> pd.DataFrame:
    """Read one CSV with float32 features. latin-1 because some labels are not valid UTF-8."""
    header = pd.read_csv(path, nrows=0, encoding="latin-1").columns
    dtypes = {c: np.float32 for c in header if c.strip() != LABEL}
    df = pd.read_csv(path, dtype=dtypes, encoding="latin-1")  # type: ignore[arg-type]
    df.columns = [c.strip() for c in df.columns]
    df[LABEL] = df[LABEL].astype(str).map(normalize_label)
    return df


def plan_targets(counts: dict[str, int], sample: int, min_per_class: int) -> dict[str, int]:
    """Rows to keep per class: proportional share, but at least min(count, min_per_class).

    The surplus created by those floors is taken from the largest class, so the total is `sample`.
    """
    total = sum(counts.values())
    if sample >= total:
        return dict(counts)
    target = {k: max(round(sample * v / total), min(v, min_per_class)) for k, v in counts.items()}
    surplus = sum(target.values()) - sample
    biggest = max(counts, key=lambda k: counts[k])
    target[biggest] = max(1, target[biggest] - surplus)
    return target


def load_cicids(
    data_dir: Path, sample: int = 200_000, seed: int = 42, min_per_class: int = 100
) -> tuple[pd.DataFrame, LoadReport]:
    """Return (features + 'Label' DataFrame of about `sample` rows, report)."""
    files = _csv_files(data_dir)
    rep = LoadReport(files=[f.name for f in files], min_per_class=min_per_class, seed=seed)

    # pass 1: label counts only (cheap), to plan a stratified sample
    counts: dict[str, int] = {}
    for f in files:
        labels = pd.read_csv(f, usecols=lambda c: c.strip() == LABEL, encoding="latin-1")
        for name, n in labels.iloc[:, 0].astype(str).map(normalize_label).value_counts().items():
            counts[str(name)] = counts.get(str(name), 0) + int(n)
    rep.raw_rows, rep.raw_label_counts = sum(counts.values()), counts
    target = plan_targets(counts, sample, min_per_class)

    # pass 2: clean each file, keep ~1.3x the target share of each class, free the rest
    rng = np.random.default_rng(seed)
    kept: list[pd.DataFrame] = []
    for f in files:
        df = _read(f)
        feats = [c for c in df.columns if c != LABEL]
        df[feats] = df[feats].replace([np.inf, -np.inf], np.nan)
        before = len(df)
        df = df.dropna()
        rep.dropped_non_finite += before - len(df)
        before = len(df)
        df = df.drop_duplicates()
        rep.dropped_duplicates += before - len(df)
        parts = []
        for name, grp in df.groupby(LABEL, sort=False):
            frac = min(1.0, 1.3 * target[str(name)] / counts[str(name)])
            parts.append(grp.sample(frac=frac, random_state=int(rng.integers(2**31))))
        kept.append(pd.concat(parts))
        del df, parts

    full = pd.concat(kept, ignore_index=True)
    del kept
    before = len(full)
    full = full.drop_duplicates()  # the same flow can appear in two files
    rep.dropped_duplicates += before - len(full)

    # final exact trim per class, then shuffle
    trimmed = [
        grp.sample(n=min(len(grp), target[str(name)]), random_state=seed)
        for name, grp in full.groupby(LABEL, sort=False)
    ]
    out = pd.concat(trimmed).sample(frac=1.0, random_state=seed).reset_index(drop=True)
    out, dropped = drop_redundant_columns(out)
    rep.dropped_columns = dropped
    rep.sample_rows = len(out)
    rep.sample_label_counts = {str(k): int(v) for k, v in out[LABEL].value_counts().items()}
    return out, rep


def drop_redundant_columns(df: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    """Drop constant columns and exact duplicate columns (CIC repeats 'Fwd Header Length')."""
    feats = [c for c in df.columns if c != LABEL]
    const = [c for c in feats if df[c].nunique(dropna=False) <= 1]
    rest = [c for c in feats if c not in const]
    dup = list(df[rest].T.duplicated()[lambda s: s].index)
    drop = const + dup
    return df.drop(columns=drop), drop
