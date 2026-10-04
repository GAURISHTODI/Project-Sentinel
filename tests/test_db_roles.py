"""Integration tests for least-privilege DB roles; skipped unless the core stack and roles exist."""

import os
import uuid

import pytest

from sentinel.common.config import get_settings

pytestmark = pytest.mark.integration

ROLES = {
    "detect": ("sentinel_detect", "DB_DETECT_PASSWORD"),
    "api": ("sentinel_api", "DB_API_PASSWORD"),
    "reader": ("sentinel_reader", "DB_READER_PASSWORD"),
}


def _dsn_for(role: str, password: str) -> str:
    owner = get_settings().database_url.get_secret_value()
    # Same host, port and database as the owner DSN, with the role's own login.
    host_part = owner.split("@", 1)[1]
    return f"postgresql://{role}:{password}@{host_part}"


@pytest.fixture
def conn_for():  # type: ignore[no-untyped-def]
    import psycopg

    def make(key: str):  # type: ignore[no-untyped-def]
        role, env = ROLES[key]
        password = os.environ.get(env, "")
        if not password:
            pytest.skip(f"{env} not set; run scripts/db_roles.sh")
        try:
            return psycopg.connect(_dsn_for(role, password), autocommit=True, connect_timeout=2)
        except psycopg.OperationalError as exc:
            pytest.skip(f"role {role} unavailable: {str(exc)[:80]}")

    return make


def _denied(conn, sql: str, params: tuple = ()) -> bool:  # type: ignore[no-untyped-def]
    import psycopg

    try:
        conn.execute(sql, params)
    except psycopg.Error:
        return True
    return False


def test_reader_can_read_but_not_write(conn_for) -> None:  # type: ignore[no-untyped-def]
    conn = conn_for("reader")
    conn.execute("SELECT count(*) FROM incidents").fetchone()
    assert _denied(
        conn,
        "INSERT INTO locked_accounts (username, reason) VALUES (%s, 'x')",
        (f"t-{uuid.uuid4().hex[:6]}",),
    )
    assert _denied(conn, "UPDATE incidents SET status = 'closed' WHERE false")
    conn.close()


def test_detect_role_writes_incidents_and_appends_audit_only(conn_for) -> None:  # type: ignore[no-untyped-def]
    conn = conn_for("detect")
    conn.execute("SELECT count(*) FROM audit_log").fetchone()
    assert not _denied(conn, "UPDATE incidents SET last_seen = now() WHERE false")
    assert _denied(conn, "UPDATE audit_log SET actor = 'forged' WHERE false")
    assert _denied(conn, "DELETE FROM audit_log WHERE false")
    assert _denied(conn, "DROP TABLE audit_log")
    conn.close()


def test_api_role_can_change_only_incident_status(conn_for) -> None:  # type: ignore[no-untyped-def]
    conn = conn_for("api")
    assert not _denied(conn, "UPDATE incidents SET status = status WHERE false")
    assert _denied(conn, "UPDATE incidents SET severity = 'low' WHERE false")
    assert _denied(conn, "DELETE FROM incidents WHERE false")
    assert _denied(conn, "UPDATE audit_log SET actor = 'forged' WHERE false")
    conn.close()


def test_audit_log_trigger_blocks_update_and_delete_for_the_owner() -> None:
    import psycopg

    with psycopg.connect(get_settings().database_url.get_secret_value(), autocommit=True) as conn:
        row = conn.execute("SELECT id FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
        if row is None:
            pytest.skip("audit_log is empty")
        with pytest.raises(psycopg.errors.RaiseException, match="append-only"):
            conn.execute("UPDATE audit_log SET actor = actor WHERE id = %s", (row[0],))
        with pytest.raises(psycopg.errors.RaiseException, match="append-only"):
            conn.execute("DELETE FROM audit_log WHERE id = %s", (row[0],))
