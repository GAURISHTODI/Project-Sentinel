"""Normalized event and detection schemas shared by every component.

All string fields come from logs and are untrusted: they are length-bounded here so a
hostile event cannot blow up memory, rules, dashboards or an LLM prompt downstream.
"""

from __future__ import annotations

import time
from typing import Annotated, Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Source = Literal["app", "auth", "network", "endpoint"]
Severity = Literal["low", "medium", "high", "critical"]

# Per-field caps for untrusted text. Longer input is truncated, never rejected.
MAX_LEN: dict[str, int] = {
    "user": 128,
    "path": 2048,
    "user_agent": 512,
    "url": 2048,
    "process_name": 260,
    "parent_process": 260,
    "command_line": 4096,
    "event_type": 64,
}

EventType = Literal[
    "http_request",
    "login",
    "flow",
    "process_create",
    "service_install",
    "powershell_script_block",
    "transaction",
]


def _new_id() -> str:
    return uuid4().hex


class NormalizedEvent(BaseModel):
    """One event from any source. `label` is for evaluation ONLY; detectors never read it."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(default_factory=_new_id)
    source: Source
    event_type: EventType
    timestamp_generated: float = Field(default_factory=time.time)  # epoch seconds
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: Annotated[int, Field(ge=0, le=65535)] | None = None
    country: str | None = Field(default=None, max_length=2)
    user: str | None = None
    method: str | None = Field(default=None, max_length=16)
    path: str | None = None
    status: Annotated[int, Field(ge=0, le=999)] | None = None
    user_agent: str | None = None
    url: str | None = None
    amount: float | None = None
    flow_features: dict[str, float] | None = None
    process_name: str | None = None
    parent_process: str | None = None
    command_line: str | None = None
    label: str | None = None  # evaluation only

    @field_validator(*MAX_LEN, mode="before")
    @classmethod
    def _truncate(cls, v: Any, info: Any) -> Any:
        limit = MAX_LEN[info.field_name]
        if isinstance(v, str) and len(v) > limit:
            return v[:limit]
        return v

    def strip_label(self) -> NormalizedEvent:
        """Copy with the evaluation label removed; the detection path only ever sees this."""
        return self.model_copy(update={"label": None})


class Detection(BaseModel):
    """Output of a rule or ML model. Exactly one of rule_id / model_name is set."""

    model_config = ConfigDict(extra="forbid")

    detection_id: str = Field(default_factory=_new_id)
    event_id: str
    rule_id: str | None = None
    model_name: str | None = None
    attack_id: str | None = None
    severity: Severity = "medium"
    score: float = Field(ge=0.0, le=1.0)
    timestamp_event: float | None = None
    timestamp_detected: float = Field(default_factory=time.time)
    src_ip: str | None = None
    user: str | None = None
    explanation: str = Field(max_length=2000)

    @model_validator(mode="after")
    def _one_detector(self) -> Detection:
        if (self.rule_id is None) == (self.model_name is None):
            raise ValueError("exactly one of rule_id or model_name must be set")
        return self
