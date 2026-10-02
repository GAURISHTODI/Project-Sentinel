"""Rule schema. Every rule YAML must have: id, title, attack_id, severity, condition, response."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from sentinel.common.schema import NormalizedEvent, Severity

# Fields a rule may read. `label` is deliberately absent: detectors never see ground truth.
EVENT_FIELDS = (set(NormalizedEvent.model_fields) - {"label", "campaign", "flow_features"}) | {
    "path_decoded",
    "user_decoded",
    "cmdline_entropy",
}
MODIFIERS = {"contains", "startswith", "endswith", "re", "gt", "gte", "lt", "lte", "exists"}


def check_field(name: str) -> None:
    field = name.split("|")[0]
    if field in {"label", "campaign"}:
        raise ValueError(f"rules must not read {field!r} (evaluation-only ground truth)")
    if field not in EVENT_FIELDS and not field.startswith("flow_"):
        raise ValueError(f"unknown event field {field!r}")


class WindowSpec(BaseModel):
    """Sliding-window threshold, per group. `distinct` counts distinct values instead of events."""

    model_config = ConfigDict(extra="forbid")

    group_by: list[str] = Field(min_length=1)
    seconds: int = Field(gt=0, le=86400)
    threshold: int = Field(gt=0)
    distinct: str | None = None
    cooldown_seconds: int | None = Field(default=None, ge=0)

    @field_validator("group_by")
    @classmethod
    def _fields(cls, v: list[str]) -> list[str]:
        for f in v:
            check_field(f)
        return v

    @field_validator("distinct")
    @classmethod
    def _distinct(cls, v: str | None) -> str | None:
        if v is not None:
            check_field(v)
        return v


class NoveltySpec(BaseModel):
    """Fire when `entity` is seen with an `attribute` value it has never had, after a baseline."""

    model_config = ConfigDict(extra="forbid")

    entity: str
    attribute: str
    min_baseline: int = Field(default=3, ge=1)

    @field_validator("entity", "attribute")
    @classmethod
    def _fields(cls, v: str) -> str:
        check_field(v)
        return v


class Condition(BaseModel):
    """`selection` entries are ORed; fields inside one entry are ANDed (Sigma semantics)."""

    model_config = ConfigDict(extra="forbid")

    selection: list[dict[str, Any]] = Field(min_length=1)
    exclude: list[dict[str, Any]] = Field(default_factory=list)
    window: WindowSpec | None = None
    novelty: NoveltySpec | None = None

    @field_validator("selection", "exclude", mode="before")
    @classmethod
    def _listify(cls, v: Any) -> Any:
        return [v] if isinstance(v, dict) else v

    @field_validator("selection", "exclude")
    @classmethod
    def _check(cls, v: list[dict[str, Any]]) -> list[dict[str, Any]]:
        for entry in v:
            for key in entry:
                check_field(key)
                _, _, mod = key.partition("|")
                if mod and mod not in MODIFIERS:
                    raise ValueError(f"unknown modifier {mod!r} in {key!r}")
        return v

    @model_validator(mode="after")
    def _one_state_kind(self) -> Condition:
        if self.window and self.novelty:
            raise ValueError("a rule may use either window or novelty, not both")
        return self


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^SEN-\d{3}$")
    title: str = Field(min_length=3, max_length=120)
    description: str = ""
    attack_id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    severity: Severity
    enabled: bool = True
    condition: Condition
    response: list[dict[str, Any]] = Field(min_length=1)

    @field_validator("response")
    @classmethod
    def _actions(cls, v: list[dict[str, Any]]) -> list[dict[str, Any]]:
        for r in v:
            if not isinstance(r.get("action"), str):
                raise ValueError("each response entry needs an 'action'")
        return v


RuleKind = Literal["match", "window", "novelty"]
