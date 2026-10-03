"""The only shape the triage agent will accept from the LLM. Anything else is rejected."""

from __future__ import annotations

import functools
import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

RULES_DIR = Path(__file__).parents[1] / "detect" / "rules" / "rules"
ATTACK_ID = r"^T\d{4}(\.\d{3})?$"
# Fixed catalogue. These are recommendations for a human analyst; the agent executes none of them.
ALLOWED_RECOMMENDATIONS = (
    "monitor",
    "review_account",
    "block_source_ip_after_review",
    "lock_account_after_review",
    "escalate_to_human",
    "no_action",
)
Recommendation = Literal[
    "monitor",
    "review_account",
    "block_source_ip_after_review",
    "lock_account_after_review",
    "escalate_to_human",
    "no_action",
]


@functools.cache
def known_attack_ids() -> frozenset[str]:
    """Techniques Sentinel itself maps to. The model may cite only these, not any well-formed id."""
    ids: set[str] = set()
    for path in RULES_DIR.glob("*.yaml"):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if data.get("attack_id"):
            ids.add(str(data["attack_id"]))
    from sentinel.detect.engine import CIC_ATTACK_MAP

    ids.update(v for v in CIC_ATTACK_MAP.values() if v)
    ids.update({"T1566", "T1657"})  # phishing URL and card-fraud detectors
    return frozenset(ids)


class TriageReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    summary: str = Field(min_length=1, max_length=800)
    attack_ids: list[str] = Field(min_length=1, max_length=5)
    severity: Literal["low", "medium", "high", "critical"]
    recommendations: list[Recommendation] = Field(min_length=1, max_length=4)
    confidence: float = Field(ge=0.0, le=1.0)

    @field_validator("attack_ids")
    @classmethod
    def _valid_attack_ids(cls, v: list[str]) -> list[str]:
        known = known_attack_ids()
        for item in v:
            if not re.fullmatch(ATTACK_ID, item) or item not in known:
                raise ValueError(f"not a technique Sentinel knows: {item!r}")
        return v
