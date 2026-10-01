"""Sigma-style rule engine: YAML rules -> Detections, with sliding windows and hot reload.

Rules only ever see a `facts` dict built from the event WITHOUT its label. Event content is
untrusted, so matching is bounded (field length caps in the schema) and every value quoted in an
explanation goes through clean_text().
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from sentinel.common.logging import get_logger
from sentinel.common.schema import Detection, NormalizedEvent
from sentinel.common.security import clean_text, url_decode
from sentinel.detect.rules.model import Rule
from sentinel.detect.rules.state import Store

log = get_logger(__name__)
DEFAULT_RULES_DIR = Path(__file__).parent / "rules"
BASE_SCORE = {"low": 0.3, "medium": 0.5, "high": 0.7, "critical": 0.9}

Facts = Mapping[str, Any]
Matcher = Callable[[Facts], bool]


def build_facts(ev: NormalizedEvent) -> dict[str, Any]:
    """Flat dict a rule can read. The evaluation `label` is excluded on purpose."""
    facts = ev.model_dump(exclude={"label"})
    for name, value in (facts.pop("flow_features") or {}).items():
        facts[f"flow_{name}"] = value
    if facts.get("path"):
        facts["path_decoded"] = url_decode(facts["path"])
    if facts.get("user"):
        facts["user_decoded"] = url_decode(facts["user"])
    return facts


def _one(field_mod: str, expected: Any) -> Matcher:
    field, _, mod = field_mod.partition("|")
    values = expected if isinstance(expected, list) else [expected]

    if mod == "exists":
        want = bool(expected)
        return lambda f: (f.get(field) is not None) == want
    if mod in {"gt", "gte", "lt", "lte"}:
        limit = float(expected)
        cmp: dict[str, Callable[[float], bool]] = {
            "gt": lambda x: x > limit,
            "gte": lambda x: x >= limit,
            "lt": lambda x: x < limit,
            "lte": lambda x: x <= limit,
        }
        op = cmp[mod]
        return lambda f: isinstance(f.get(field), int | float) and op(float(f[field]))

    if mod == "re":
        pats = [re.compile(str(v), re.IGNORECASE) for v in values]
        return lambda f: isinstance(f.get(field), str) and any(p.search(f[field]) for p in pats)

    lowered = [str(v).lower() for v in values]

    def text_match(f: Facts) -> bool:
        raw = f.get(field)
        if raw is None:
            return False
        s = str(raw).lower()
        if mod == "contains":
            return any(v in s for v in lowered)
        if mod == "startswith":
            return any(s.startswith(v) for v in lowered)
        if mod == "endswith":
            return any(s.endswith(v) for v in lowered)
        return s in lowered  # plain equality, case-insensitive, any-of

    return text_match


def compile_selection(sel: dict[str, Any]) -> Matcher:
    matchers = [_one(k, v) for k, v in sel.items()]
    return lambda f: all(m(f) for m in matchers)


@dataclass
class CompiledRule:
    rule: Rule
    selection: list[tuple[dict[str, Any], Matcher]]
    exclude: list[Matcher]

    def matched(self, facts: Facts) -> dict[str, Any] | None:
        """Return the selection entry that matched (for the explanation), or None."""
        if any(m(facts) for m in self.exclude):
            return None
        for entry, m in self.selection:
            if m(facts):
                return entry
        return None


def compile_rule(rule: Rule) -> CompiledRule:
    c = rule.condition
    return CompiledRule(
        rule,
        [(e, compile_selection(e)) for e in c.selection],
        [compile_selection(e) for e in c.exclude],
    )


def load_rules(directory: Path) -> list[Rule]:
    rules: list[Rule] = []
    seen: set[str] = set()
    for path in sorted(directory.glob("*.y*ml")):
        rule = Rule.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
        if rule.id in seen:
            raise ValueError(f"duplicate rule id {rule.id} in {path.name}")
        seen.add(rule.id)
        rules.append(rule)
    return rules


class RuleEngine:
    def __init__(
        self,
        store: Store,
        rules_dir: Path = DEFAULT_RULES_DIR,
        check_interval: float = 2.0,
    ) -> None:
        self.store, self.dir, self.check_interval = store, rules_dir, check_interval
        self._compiled: list[CompiledRule] = []
        self._sig: tuple[tuple[str, int, int], ...] = ()
        self._last_check = 0.0
        self.last_error: str | None = None
        self.reload_if_changed(force=True)

    @property
    def rules(self) -> list[Rule]:
        return [c.rule for c in self._compiled]

    def _signature(self) -> tuple[tuple[str, int, int], ...]:
        out = []
        for p in sorted(self.dir.glob("*.y*ml")):
            st = p.stat()
            out.append((p.name, st.st_mtime_ns, st.st_size))
        return tuple(out)

    def reload_if_changed(self, force: bool = False) -> bool:
        """Hot reload. A broken edit keeps the previous good rules and records last_error."""
        sig = self._signature()
        if not force and sig == self._sig:
            return False
        self._sig = sig  # remember even on failure so a bad file is not re-parsed every event
        try:
            rules = load_rules(self.dir)
            self._compiled = [compile_rule(r) for r in rules]
            self.last_error = None
            log.info("rules loaded", extra={"fields": {"count": len(rules)}})
        except (yaml.YAMLError, ValidationError, ValueError, OSError, re.error) as exc:
            self.last_error = clean_text(exc, 500)
            log.error("rule reload failed", extra={"fields": {"error": self.last_error}})
            return False
        return True

    def evaluate(self, ev: NormalizedEvent) -> list[Detection]:
        now = time.monotonic()
        if now - self._last_check >= self.check_interval:
            self._last_check = now
            self.reload_if_changed()
        facts = build_facts(ev)
        out: list[Detection] = []
        for cr in self._compiled:
            if not cr.rule.enabled:
                continue
            entry = cr.matched(facts)
            if entry is None:
                continue
            det = self._stateful(cr, ev, facts, entry)
            if det is not None:
                out.append(det)
        return out

    # ------------------------------------------------------------------ internals

    def _detection(
        self, cr: CompiledRule, ev: NormalizedEvent, score: float, why: str
    ) -> Detection:
        return Detection(
            event_id=ev.event_id,
            rule_id=cr.rule.id,
            attack_id=cr.rule.attack_id,
            severity=cr.rule.severity,
            score=min(score, 0.99),
            timestamp_event=ev.timestamp_generated,
            src_ip=ev.src_ip,
            user=ev.user,
            explanation=f"{cr.rule.title}: {why}"[:2000],
        )

    def _stateful(
        self, cr: CompiledRule, ev: NormalizedEvent, facts: Facts, entry: dict[str, Any]
    ) -> Detection | None:
        rule, cond = cr.rule, cr.rule.condition
        base = BASE_SCORE[rule.severity]
        ts = ev.timestamp_generated

        if cond.window is not None:
            w = cond.window
            parts = [facts.get(g) for g in w.group_by]
            if any(p is None for p in parts):
                return None
            group = "|".join(str(p) for p in parts)
            member = str(facts.get(w.distinct)) if w.distinct else ev.event_id
            if w.distinct and facts.get(w.distinct) is None:
                return None
            count = self.store.record(f"{rule.id}:{group}", ts, member, w.seconds)
            if count < w.threshold:
                return None
            cooldown = w.seconds if w.cooldown_seconds is None else w.cooldown_seconds
            if not self.store.claim(f"{rule.id}:{group}", ts, cooldown):
                return None
            what = f"distinct {w.distinct} values" if w.distinct else "matching events"
            who = ", ".join(f"{g}={clean_text(p)}" for g, p in zip(w.group_by, parts, strict=True))
            why = f"{count} {what} for {who} within {w.seconds}s (threshold {w.threshold})"
            return self._detection(cr, ev, base + min(0.25, 0.05 * count / w.threshold), why)

        if cond.novelty is not None:
            n = cond.novelty
            entity, attr = facts.get(n.entity), facts.get(n.attribute)
            if entity is None or attr is None:
                return None
            if not self.store.novel(f"{rule.id}:{entity}", str(attr), n.min_baseline):
                return None
            why = (
                f"{n.entity}={clean_text(entity)} seen with new {n.attribute}="
                f"{clean_text(attr)} after {n.min_baseline}+ known values"
            )
            return self._detection(cr, ev, base, why)

        shown = ", ".join(
            f"{k.split('|')[0]}={clean_text(facts.get(k.split('|')[0]), 80)}" for k in entry
        )
        return self._detection(cr, ev, base, f"pattern matched ({shown})")
