"""Read-side data access for the API: incidents and users. PostgreSQL or in-memory (tests)."""

from __future__ import annotations

from typing import Any, Protocol

import psycopg
from pydantic import BaseModel

from sentinel.respond.repo import MemoryRepo

STATUSES = ("open", "triaged", "closed")
SEVERITIES = ("low", "medium", "high", "critical")
ROLES = ("analyst", "admin")


class User(BaseModel):
    username: str
    password_hash: str
    role: str
    disabled: bool = False


class UserStore(Protocol):
    def get(self, username: str) -> User | None: ...
    def create(self, username: str, password_hash: str, role: str) -> None: ...


class IncidentReader(Protocol):
    def list_incidents(
        self, status: str | None, severity: str | None, limit: int, offset: int
    ) -> list[dict[str, Any]]: ...
    def get_incident(self, incident_id: int) -> dict[str, Any] | None: ...
    def set_status(self, incident_id: int, status: str) -> bool: ...


def _public(row: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "id",
        "detector",
        "attack_id",
        "severity",
        "score",
        "src_ip",
        "user",
        "status",
        "event_count",
        "explanation",
        "detected_at",
        "first_event_ts",
        "responded_ts",
    )
    return {k: row.get(k) for k in keys}


class MemoryUsers:
    def __init__(self) -> None:
        self.users: dict[str, User] = {}

    def get(self, username: str) -> User | None:
        return self.users.get(username)

    def create(self, username: str, password_hash: str, role: str) -> None:
        if username in self.users:
            raise ValueError("user exists")
        self.users[username] = User(username=username, password_hash=password_hash, role=role)


class MemoryIncidents:
    def __init__(self, repo: MemoryRepo) -> None:
        self.repo = repo

    def _rows(self) -> list[dict[str, Any]]:
        return sorted(self.repo.incidents.values(), key=lambda r: r["id"], reverse=True)

    def list_incidents(
        self, status: str | None, severity: str | None, limit: int, offset: int
    ) -> list[dict[str, Any]]:
        rows = [
            r
            for r in self._rows()
            if (status is None or r["status"] == status)
            and (severity is None or r["severity"] == severity)
        ]
        return [_public(r) for r in rows[offset : offset + limit]]

    def get_incident(self, incident_id: int) -> dict[str, Any] | None:
        return next((_public(r) for r in self._rows() if r["id"] == incident_id), None)

    def set_status(self, incident_id: int, status: str) -> bool:
        for r in self.repo.incidents.values():
            if r["id"] == incident_id:
                r["status"] = status
                return True
        return False


_COLS = (
    "id, coalesce(rule_id, model_name) AS detector, attack_id, severity, score, "
    "host(src_ip) AS src_ip, username AS user, status, event_count, explanation, "
    "extract(epoch FROM detected_at) AS detected_at, first_event_ts, responded_ts"
)


class PgIncidents:
    def __init__(self, dsn: str) -> None:
        self._conn = psycopg.connect(dsn, autocommit=True, row_factory=psycopg.rows.dict_row)

    def close(self) -> None:
        self._conn.close()

    def list_incidents(
        self, status: str | None, severity: str | None, limit: int, offset: int
    ) -> list[dict[str, Any]]:
        return self._conn.execute(
            f"SELECT {_COLS} FROM incidents WHERE (%s::text IS NULL OR status = %s) "  # noqa: S608
            "AND (%s::text IS NULL OR severity = %s) ORDER BY id DESC LIMIT %s OFFSET %s",
            (status, status, severity, severity, limit, offset),
        ).fetchall()

    def get_incident(self, incident_id: int) -> dict[str, Any] | None:
        return self._conn.execute(
            f"SELECT {_COLS} FROM incidents WHERE id = %s",  # noqa: S608
            (incident_id,),
        ).fetchone()

    def set_status(self, incident_id: int, status: str) -> bool:
        cur = self._conn.execute(
            "UPDATE incidents SET status = %s WHERE id = %s", (status, incident_id)
        )
        return cur.rowcount == 1


class PgUsers:
    def __init__(self, dsn: str) -> None:
        self._conn = psycopg.connect(dsn, autocommit=True)

    def close(self) -> None:
        self._conn.close()

    def get(self, username: str) -> User | None:
        row = self._conn.execute(
            "SELECT username, password_hash, role, disabled FROM users WHERE username = %s",
            (username,),
        ).fetchone()
        return (
            User(username=row[0], password_hash=row[1], role=row[2], disabled=row[3])
            if row
            else None
        )

    def create(self, username: str, password_hash: str, role: str) -> None:
        self._conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
            (username, password_hash, role),
        )
