"""Response policy (YAML): which actions a detection triggers, and what must never be blocked.

Resolution order for one detection:
  1. policy `overrides[<rule_id or model_name>]`, if present
  2. the rule's own `response:` list, if it has one
  3. policy `severity_defaults[<severity>]`
Then: `create_incident` is always added (no response without a record), and escalation may add
`block_ip` when one source trips several distinct detectors in a short time.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from sentinel.common.schema import Detection, Severity

ActionName = Literal["block_ip", "lock_account", "rate_limit", "create_incident", "notify"]
DEFAULT_POLICY = Path(__file__).parent / "policy.yaml"
_SEVERITY_ORDER = ["low", "medium", "high", "critical"]


class ActionSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: ActionName
    params: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def parse(cls, raw: dict[str, Any]) -> ActionSpec:
        data = dict(raw)
        return cls(action=data.pop("action"), params=data)


class Escalation(BaseModel):
    """A source tripping `distinct_detectors` different detectors in `window_seconds` is blocked."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    distinct_detectors: int = Field(default=3, ge=2)
    window_seconds: int = Field(default=300, gt=0)
    block_ttl_seconds: int = Field(default=3600, gt=0)


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dry_run: bool = False
    protected_cidrs: list[str] = Field(default_factory=list)
    min_block_severity: Severity = "medium"
    notify_cooldown_seconds: int = Field(default=300, ge=0)
    escalation: Escalation = Field(default_factory=Escalation)
    severity_defaults: dict[Severity, list[dict[str, Any]]] = Field(default_factory=dict)
    overrides: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)

    @field_validator("protected_cidrs")
    @classmethod
    def _valid_cidrs(cls, v: list[str]) -> list[str]:
        for c in v:
            ipaddress.ip_network(c, strict=False)
        return v

    @field_validator("severity_defaults", "overrides")
    @classmethod
    def _valid_actions(cls, v: dict[Any, list[dict[str, Any]]]) -> dict[Any, list[dict[str, Any]]]:
        for entries in v.values():
            for entry in entries:
                ActionSpec.parse(entry)  # raises on unknown action names
        return v

    def is_protected(self, ip: str) -> bool:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(c, strict=False) for c in self.protected_cidrs)

    def severity_allows_block(self, severity: Severity) -> bool:
        return _SEVERITY_ORDER.index(severity) >= _SEVERITY_ORDER.index(self.min_block_severity)

    def actions_for(
        self, det: Detection, rule_response: list[dict[str, Any]] | None = None
    ) -> list[ActionSpec]:
        detector = det.rule_id or det.model_name or ""
        raw = (
            self.overrides.get(detector)
            or rule_response
            or self.severity_defaults.get(det.severity)
        )
        specs = [ActionSpec.parse(r) for r in (raw or [])]
        if not any(s.action == "create_incident" for s in specs):
            specs.insert(0, ActionSpec(action="create_incident"))
        return specs


def load_policy(path: Path = DEFAULT_POLICY) -> Policy:
    return Policy.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
