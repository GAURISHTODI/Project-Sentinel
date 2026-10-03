"""Load trained network-IDS models and score a single flow. Inputs are untrusted."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

from sentinel.detect.ml.url_features import url_features

DEFAULT_DIR = Path("models/network")
DEFAULT_PHISHING_DIR = Path("models/phishing")
MIN_FEATURE_COVERAGE = 0.8  # refuse to score a flow that is mostly missing features


class NetworkPredictor:
    def __init__(
        self, model_dir: Path = DEFAULT_DIR, model: str = "xgb_binary", threshold: float = 0.5
    ) -> None:
        if not 0.0 < threshold < 1.0:
            raise ValueError("threshold must be in (0, 1)")
        self.threshold = threshold
        bundle = joblib.load(model_dir / f"{model}.joblib")
        self._pipe = bundle["pipeline"]
        self.features: list[str] = bundle["features"]
        self.classes: list[str] = bundle["classes"]
        self.model_name = f"network-{model}"
        card = model_dir / "model_card.json"
        self.card: dict[str, Any] = json.loads(card.read_text()) if card.exists() else {}

    def _vector(self, flow: Mapping[str, float]) -> pd.DataFrame:
        present = [f for f in self.features if f in flow]
        if len(present) < MIN_FEATURE_COVERAGE * len(self.features):
            raise ValueError(f"flow has {len(present)}/{len(self.features)} required features")
        vec = np.zeros((1, len(self.features)), dtype=np.float32)
        for i, name in enumerate(self.features):
            v = flow.get(name)
            # untrusted: ignore non-numeric, NaN and infinite values (treated as 0)
            if isinstance(v, int | float) and not isinstance(v, bool) and math.isfinite(v):
                vec[0, i] = v
        return pd.DataFrame(vec, columns=self.features)

    def attack_probability(self, flow: Mapping[str, float]) -> float:
        """P(attack) for a binary model."""
        return float(self._pipe.predict_proba(self._vector(flow))[0, 1])

    def is_attack(self, flow: Mapping[str, float]) -> tuple[bool, float]:
        p = self.attack_probability(flow)
        return p >= self.threshold, p

    def attack_type(self, flow: Mapping[str, float]) -> tuple[str, float]:
        """Most likely class and its probability for a multi-class model."""
        probs = self._pipe.predict_proba(self._vector(flow))[0]
        i = int(np.argmax(probs))
        return self.classes[i], float(probs[i])


class PhishingPredictor:
    """Scores one URL string with the trained lexical phishing model. Input is untrusted."""

    def __init__(self, model_dir: Path = DEFAULT_PHISHING_DIR, threshold: float = 0.5) -> None:
        if not 0.0 < threshold < 1.0:
            raise ValueError("threshold must be in (0, 1)")
        self.threshold = threshold
        bundle = joblib.load(model_dir / "url_model.joblib")
        self._model = bundle["model"]
        self.features: list[str] = bundle["features"]
        self.model_name = "phishing-url"

    def phishing_probability(self, url: str) -> float:
        vec = pd.DataFrame([url_features(url)], columns=self.features)
        return float(self._model.predict_proba(vec)[0, 1])
