"""The five response actions. Every action is idempotent and returns a typed outcome.

Redis keys (the Spring Boot gateway in T8 reads the first two):
  sen:blocklist:<ip>   -> JSON {detector, ts}, TTL          (HTTP 403 at the gateway)
  sen:ratelimit:<ip>   -> requests/minute, TTL
  sen:locked:<user>    -> reason, TTL                        (login refused)
Idempotent means: repeating an action for the same target does not stack, extend or duplicate it.
"""

from __future__ import annotations

import ipaddress
import json
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

import redis

from sentinel.common.schema import Detection
from sentinel.common.security import clean_text
from sentinel.respond.notify import Notifier
from sentinel.respond.policy import Policy
from sentinel.respond.repo import Repository

BLOCK_PREFIX = "sen:blocklist:"
RATE_PREFIX = "sen:ratelimit:"
LOCK_PREFIX = "sen:locked:"
MAX_TTL = 7 * 24 * 3600  # no action may outlive a week, whatever the policy says


class Outcome(StrEnum):
    APPLIED = "applied"
    ALREADY_ACTIVE = "already_active"
    PROTECTED = "protected"
    BELOW_SEVERITY = "below_severity"
    NO_TARGET = "no_target"
    DRY_RUN = "dry_run"
    FAILED = "failed"


@dataclass
class ActionResult:
    action: str
    outcome: Outcome
    target: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)


def valid_ip(value: str | None) -> str | None:
    """Return the canonical IP string, or None. Log-derived addresses are never trusted as-is."""
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _ttl(params: dict[str, Any], default: int) -> int:
    try:
        ttl = int(params.get("ttl_seconds", default))
    except (TypeError, ValueError):
        ttl = default
    return max(1, min(ttl, MAX_TTL))


class Actions:
    def __init__(
        self,
        r: redis.Redis,
        repo: Repository,
        notifier: Notifier,
        policy: Policy,
    ) -> None:
        self.r, self.repo, self.notifier, self.policy = r, repo, notifier, policy

    # ------------------------------------------------------------------ enforcement

    def block_ip(self, det: Detection, params: dict[str, Any]) -> ActionResult:
        ip = valid_ip(det.src_ip)
        if ip is None:
            return ActionResult("block_ip", Outcome.NO_TARGET)
        if self.policy.is_protected(ip):
            return ActionResult("block_ip", Outcome.PROTECTED, ip)
        if not self.policy.severity_allows_block(det.severity) and not params.get("force"):
            return ActionResult("block_ip", Outcome.BELOW_SEVERITY, ip)
        ttl = _ttl(params, 3600)
        if self.policy.dry_run:
            return ActionResult("block_ip", Outcome.DRY_RUN, ip, {"ttl": ttl})
        value = json.dumps({"detector": det.rule_id or det.model_name, "ts": time.time()})
        if self.r.set(BLOCK_PREFIX + ip, value, nx=True, ex=ttl):
            return ActionResult("block_ip", Outcome.APPLIED, ip, {"ttl": ttl})
        return ActionResult("block_ip", Outcome.ALREADY_ACTIVE, ip)

    def rate_limit(self, det: Detection, params: dict[str, Any]) -> ActionResult:
        ip = valid_ip(det.src_ip)
        if ip is None:
            return ActionResult("rate_limit", Outcome.NO_TARGET)
        if self.policy.is_protected(ip):
            return ActionResult("rate_limit", Outcome.PROTECTED, ip)
        limit = max(1, int(params.get("limit_per_minute", 30)))
        ttl = _ttl(params, 600)
        if self.policy.dry_run:
            return ActionResult("rate_limit", Outcome.DRY_RUN, ip, {"limit": limit})
        if self.r.set(RATE_PREFIX + ip, limit, nx=True, ex=ttl):
            return ActionResult("rate_limit", Outcome.APPLIED, ip, {"limit": limit, "ttl": ttl})
        return ActionResult("rate_limit", Outcome.ALREADY_ACTIVE, ip)

    def lock_account(self, det: Detection, params: dict[str, Any]) -> ActionResult:
        user = (det.user or "").strip()
        if not user:
            return ActionResult("lock_account", Outcome.NO_TARGET)
        target = clean_text(user, 128)
        ttl = _ttl(params, 1800)
        if self.policy.dry_run:
            return ActionResult("lock_account", Outcome.DRY_RUN, target)
        reason = f"{det.rule_id or det.model_name}: {clean_text(det.explanation, 200)}"
        if not self.r.set(LOCK_PREFIX + user, reason, nx=True, ex=ttl):
            return ActionResult("lock_account", Outcome.ALREADY_ACTIVE, target)
        self.repo.lock_account(user, reason, time.time() + ttl)
        return ActionResult("lock_account", Outcome.APPLIED, target, {"ttl": ttl})

    # ------------------------------------------------------------------ records and alerts

    def create_incident(self, det: Detection, params: dict[str, Any]) -> ActionResult:
        res = self.repo.create_incident(det)
        outcome = Outcome.APPLIED if res.created else Outcome.ALREADY_ACTIVE
        return ActionResult(
            "create_incident", outcome, str(res.incident_id), {"id": res.incident_id}
        )

    def notify(self, det: Detection, params: dict[str, Any]) -> ActionResult:
        if self.policy.dry_run:  # checked first: a dry run must not consume the cooldown
            return ActionResult("notify", Outcome.DRY_RUN)
        cooldown = self.policy.notify_cooldown_seconds
        key = f"sen:notified:{det.rule_id or det.model_name}:{det.src_ip or det.user}"
        if cooldown and not self.r.set(key, 1, nx=True, ex=cooldown):
            return ActionResult("notify", Outcome.ALREADY_ACTIVE)
        delivered = self.notifier.send(det)
        return ActionResult("notify", Outcome.APPLIED if delivered else Outcome.FAILED)

    # ------------------------------------------------------------------ analyst overrides

    def unblock_ip(self, ip: str, actor: str) -> bool:
        clean = valid_ip(ip)
        if clean is None:
            raise ValueError("not an IP address")
        removed = bool(self.r.delete(BLOCK_PREFIX + clean))
        self.repo.audit(actor, "unblock_ip", clean, {"removed": removed})
        return removed

    def unlock_account(self, user: str, actor: str) -> bool:
        removed = bool(self.r.delete(LOCK_PREFIX + user))
        removed = self.repo.unlock_account(user) or removed
        self.repo.audit(actor, "unlock_account", clean_text(user, 128), {"removed": removed})
        return removed
