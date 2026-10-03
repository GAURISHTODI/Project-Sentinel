"""Turns a Detection into executed actions: policy -> escalation -> actions -> audit -> timing."""

from __future__ import annotations

import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx
import psycopg
import redis

from sentinel.common import metrics
from sentinel.common.logging import get_logger
from sentinel.common.schema import Detection
from sentinel.common.security import clean_text
from sentinel.detect.rules.state import Store
from sentinel.respond.actions import ActionResult, Actions, Outcome, valid_ip
from sentinel.respond.policy import ActionSpec, Policy
from sentinel.respond.repo import Repository, incident_key

log = get_logger(__name__)


@dataclass
class _Memo:
    incident_id: int
    expires: float
    pending: int = 0


ENFORCEMENT = {"block_ip", "rate_limit", "lock_account"}
# Errors an action may raise. Anything else is a bug and must surface, not be swallowed.
EXPECTED_ERRORS = (redis.RedisError, psycopg.Error, httpx.HTTPError, ValueError, TypeError)


class Responder:
    def __init__(
        self,
        policy: Policy,
        actions: Actions,
        repo: Repository,
        store: Store,
        rule_responses: dict[str, list[dict[str, Any]]] | None = None,
        clock: Callable[[], float] = time.time,
        suppress_seconds: float = 30.0,
    ) -> None:
        self.policy, self.actions, self.repo, self.store = policy, actions, repo, store
        self.rule_responses = rule_responses or {}
        self.clock = clock
        self.stats: Counter[tuple[str, str]] = Counter()
        # Repeat suppression: a detection for an incident handled in the last `suppress_seconds`
        # is counted in memory and flushed to the database in batches, instead of re-running every
        # action (each one a network round trip). Restart-safe: actions are idempotent anyway.
        self.suppress_seconds = suppress_seconds
        self._memo: dict[str, _Memo] = {}

    def _plan(self, det: Detection) -> list[ActionSpec]:
        detector = det.rule_id or det.model_name or ""
        specs = self.policy.actions_for(det, self.rule_responses.get(detector))
        esc, ip = self.policy.escalation, valid_ip(det.src_ip)
        if esc.enabled and ip and detector:
            ts = det.timestamp_event or det.timestamp_detected
            distinct = self.store.record(f"esc:{ip}", ts, detector, esc.window_seconds)
            if distinct >= esc.distinct_detectors and not any(
                s.action == "block_ip" for s in specs
            ):
                specs.append(
                    ActionSpec(
                        action="block_ip",
                        params={
                            "ttl_seconds": esc.block_ttl_seconds,
                            "force": True,
                            "reason": f"escalation: {distinct} detectors in {esc.window_seconds}s",
                        },
                    )
                )
        return specs

    def _run(self, spec: ActionSpec, det: Detection) -> ActionResult:
        fn = getattr(self.actions, spec.action)
        try:
            return fn(det, spec.params)  # type: ignore[no-any-return]
        except EXPECTED_ERRORS as exc:
            log.error(
                "action failed",
                extra={"fields": {"action": spec.action, "error": clean_text(exc, 200)}},
            )
            return ActionResult(spec.action, Outcome.FAILED, detail={"error": clean_text(exc, 200)})

    def handle(self, det: Detection) -> list[ActionResult]:
        """Run every planned action. One failing action never stops the others."""
        key = incident_key(det)
        now = self.clock()
        memo = self._memo.get(key)
        if memo is not None:
            if now < memo.expires:
                memo.pending += 1
                self.stats[("suppressed", "repeat")] += 1
                return []
            self._flush_one(memo, now)
        results: list[ActionResult] = []
        incident_id: int | None = None
        started = time.perf_counter()
        for spec in self._plan(det):
            res = self._run(spec, det)
            res.ts = self.clock()
            results.append(res)
            self.stats[(res.action, res.outcome.value)] += 1
            metrics.ACTIONS.labels(action=res.action, outcome=res.outcome.value).inc()
            if res.action == "create_incident" and "id" in res.detail:
                incident_id = int(res.detail["id"])
            if res.outcome in (Outcome.APPLIED, Outcome.FAILED):
                self._audit(det, res)
        metrics.RESPONSE_SECONDS.observe(time.perf_counter() - started)
        if incident_id is not None and self.suppress_seconds > 0:
            self._memo[key] = _Memo(incident_id, now + self.suppress_seconds)
        if incident_id is not None and any(
            r.action in ENFORCEMENT and r.outcome == Outcome.APPLIED for r in results
        ):
            self._safely(self.repo.mark_responded, incident_id, self.clock())
        return results

    def _flush_one(self, memo: _Memo, now: float) -> None:
        if memo.pending:
            self._safely(self.repo.bump_incident, memo.incident_id, memo.pending, now)
            memo.pending = 0

    def flush(self) -> None:
        """Write batched repeat counts to the database and drop expired memos."""
        now = self.clock()
        for key, memo in list(self._memo.items()):
            self._flush_one(memo, now)
            if now >= memo.expires:
                del self._memo[key]

    def _audit(self, det: Detection, res: ActionResult) -> None:
        self._safely(
            self.repo.audit,
            "sentinel-responder",
            res.action,
            res.target,
            {
                "outcome": res.outcome.value,
                "detector": det.rule_id or det.model_name,
                "event_id": det.event_id,
                "severity": det.severity,
                **res.detail,
            },
        )

    @staticmethod
    def _safely(fn: Callable[..., Any], *args: Any) -> None:
        try:
            fn(*args)
        except EXPECTED_ERRORS as exc:
            log.error("repo write failed", extra={"fields": {"error": clean_text(exc, 200)}})
