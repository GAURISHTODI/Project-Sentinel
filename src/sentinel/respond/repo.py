"""Incident / lock / audit persistence. PostgreSQL in production, in-memory for tests.

The audit log is a hash chain: each row's hash covers the previous row's hash, so editing or
deleting a past row breaks verification (checked by `verify_chain`).
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

import psycopg

from sentinel.common.schema import Detection

GENESIS = "0" * 64


def row_hash(prev: str, ts: str, actor: str, action: str, target: str | None, detail: str) -> str:
    material = "|".join([prev, ts, actor, action, target or "", detail])
    return hashlib.sha256(material.encode()).hexdigest()


def incident_key(det: Detection) -> str:
    """One open incident per detector + entity + hour: repeats of the same attack are grouped."""
    entity = det.src_ip or det.user or "unknown"
    hour = int((det.timestamp_event or det.timestamp_detected) // 3600)
    return f"{det.rule_id or det.model_name}|{entity}|{hour}"


@dataclass
class IncidentResult:
    incident_id: int
    created: bool  # False when the detection was folded into an existing open incident


class Repository(Protocol):
    def create_incident(self, det: Detection) -> IncidentResult: ...
    def lock_account(self, user: str, reason: str, until_ts: float | None) -> bool: ...
    def unlock_account(self, user: str) -> bool: ...
    def mark_responded(self, incident_id: int, ts: float) -> None: ...
    def bump_incident(self, incident_id: int, count: int, ts: float) -> None: ...
    def audit(
        self, actor: str, action: str, target: str | None, detail: dict[str, Any]
    ) -> None: ...
    def verify_chain(self) -> tuple[bool, int]: ...


class MemoryRepo:
    def __init__(self) -> None:
        self.incidents: dict[str, dict[str, Any]] = {}
        self.locked: dict[str, dict[str, Any]] = {}
        self.audit_rows: list[dict[str, Any]] = []
        self._next_id = 1

    def create_incident(self, det: Detection) -> IncidentResult:
        key = incident_key(det)
        row = self.incidents.get(key)
        if row is not None and row["status"] == "open":
            row["event_count"] += 1
            row["score"] = max(row["score"], det.score)
            return IncidentResult(row["id"], False)
        row = {
            "id": self._next_id,
            "status": "open",
            "event_count": 1,
            "score": det.score,
            "detector": det.rule_id or det.model_name,
            "src_ip": det.src_ip,
            "user": det.user,
            "severity": det.severity,
            "first_event_ts": det.timestamp_event,
            "responded_ts": None,
            "explanation": det.explanation,
            "attack_id": det.attack_id,
            "detected_at": det.timestamp_detected,
        }
        self._next_id += 1
        self.incidents[key] = row
        return IncidentResult(row["id"], True)

    def lock_account(self, user: str, reason: str, until_ts: float | None) -> bool:
        if user in self.locked:
            return False
        self.locked[user] = {"reason": reason, "until": until_ts}
        return True

    def unlock_account(self, user: str) -> bool:
        return self.locked.pop(user, None) is not None

    def bump_incident(self, incident_id: int, count: int, ts: float) -> None:
        for row in self.incidents.values():
            if row["id"] == incident_id:
                row["event_count"] += count

    def mark_responded(self, incident_id: int, ts: float) -> None:
        for row in self.incidents.values():
            if row["id"] == incident_id and row["responded_ts"] is None:
                row["responded_ts"] = ts

    def audit(self, actor: str, action: str, target: str | None, detail: dict[str, Any]) -> None:
        prev = self.audit_rows[-1]["row_hash"] if self.audit_rows else GENESIS
        ts = datetime.now(UTC).isoformat()
        body = json.dumps(detail, sort_keys=True, default=str)
        self.audit_rows.append(
            {
                "ts": ts,
                "actor": actor,
                "action": action,
                "target": target,
                "detail": body,
                "prev_hash": prev,
                "row_hash": row_hash(prev, ts, actor, action, target, body),
            }
        )

    def verify_chain(self) -> tuple[bool, int]:
        prev = GENESIS
        for i, r in enumerate(self.audit_rows):
            ok = r["prev_hash"] == prev and r["row_hash"] == row_hash(
                prev, r["ts"], r["actor"], r["action"], r["target"], r["detail"]
            )
            if not ok:
                return False, i
            prev = r["row_hash"]
        return True, len(self.audit_rows)


class PgRepo:
    """PostgreSQL implementation. One autocommit connection; all SQL is parameterised."""

    def __init__(self, dsn: str) -> None:
        self._conn = psycopg.connect(dsn, autocommit=True)

    def close(self) -> None:
        self._conn.close()

    def create_incident(self, det: Detection) -> IncidentResult:
        detected_at = datetime.fromtimestamp(det.timestamp_detected, UTC)
        row = self._conn.execute(
            """
            INSERT INTO incidents (event_id, rule_id, model_name, attack_id, severity, score,
                                   src_ip, username, explanation, detected_at, last_seen,
                                   dedupe_key, first_event_ts)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (dedupe_key) WHERE status = 'open' DO UPDATE
               SET event_count = incidents.event_count + 1,
                   last_seen   = EXCLUDED.last_seen,
                   score       = GREATEST(incidents.score, EXCLUDED.score)
            RETURNING id, (xmax = 0) AS inserted
            """,
            (
                det.event_id,
                det.rule_id,
                det.model_name,
                det.attack_id,
                det.severity,
                det.score,
                det.src_ip,
                det.user,
                det.explanation,
                detected_at,
                detected_at,
                incident_key(det),
                det.timestamp_event,
            ),
        ).fetchone()
        if row is None:  # INSERT ... RETURNING always yields a row
            raise RuntimeError("incident upsert returned no row")
        return IncidentResult(int(row[0]), bool(row[1]))

    def lock_account(self, user: str, reason: str, until_ts: float | None) -> bool:
        until = datetime.fromtimestamp(until_ts, UTC) if until_ts else None
        cur = self._conn.execute(
            "INSERT INTO locked_accounts (username, reason, locked_until) VALUES (%s,%s,%s) "
            "ON CONFLICT (username) DO NOTHING",
            (user, reason, until),
        )
        return cur.rowcount == 1

    def unlock_account(self, user: str) -> bool:
        cur = self._conn.execute("DELETE FROM locked_accounts WHERE username = %s", (user,))
        return cur.rowcount == 1

    def bump_incident(self, incident_id: int, count: int, ts: float) -> None:
        self._conn.execute(
            "UPDATE incidents SET event_count = event_count + %s, last_seen = %s WHERE id = %s",
            (count, datetime.fromtimestamp(ts, UTC), incident_id),
        )

    def mark_responded(self, incident_id: int, ts: float) -> None:
        self._conn.execute(
            "UPDATE incidents SET responded_ts = %s WHERE id = %s AND responded_ts IS NULL",
            (ts, incident_id),
        )

    def audit(self, actor: str, action: str, target: str | None, detail: dict[str, Any]) -> None:
        body = json.dumps(detail, sort_keys=True, default=str)
        with self._conn.transaction():
            self._conn.execute("SELECT pg_advisory_xact_lock(7001)")  # serialise the chain
            last = self._conn.execute(
                "SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1"
            ).fetchone()
            prev = last[0] if last and last[0] else GENESIS
            ts = datetime.now(UTC)
            h = row_hash(prev, ts.isoformat(), actor, action, target, body)
            self._conn.execute(
                "INSERT INTO audit_log (ts, actor, action, target, detail, prev_hash, row_hash) "
                "VALUES (%s,%s,%s,%s,%s::jsonb,%s,%s)",
                (ts, actor, action, target, body, prev, h),
            )

    def verify_chain(self) -> tuple[bool, int]:
        prev = GENESIS
        n = 0
        for ts, actor, action, target, detail, p, h in self._conn.execute(
            "SELECT ts, actor, action, target, detail::text, prev_hash, row_hash "
            "FROM audit_log ORDER BY id"
        ):
            # jsonb re-serialises with its own spacing; compare via canonical JSON
            canon = json.dumps(json.loads(detail), sort_keys=True, default=str)
            if p != prev or h != row_hash(
                prev, ts.astimezone(UTC).isoformat(), actor, action, target, canon
            ):
                return False, n
            prev = h
            n += 1
        return True, n


def now() -> float:
    return time.time()
