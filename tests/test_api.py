import json
import time
from pathlib import Path

import fakeredis
import jwt
import pytest
from fastapi.testclient import TestClient

from sentinel.api.app import Deps, create_app
from sentinel.api.security import (
    ALGORITHM,
    ISSUER,
    create_token,
    decode_token,
    hash_password,
    verify_password,
)
from sentinel.api.store import MemoryIncidents, MemoryUsers
from sentinel.common.schema import Detection
from sentinel.respond.actions import Actions
from sentinel.respond.notify import Notifier
from sentinel.respond.policy import load_policy
from sentinel.respond.repo import MemoryRepo

SECRET = "unit-test-secret-" + "x" * 32  # noqa: S105
PASSWORDS = {"alice": "alice-password-1", "root": "root-password-123"}


class Env:
    def __init__(self, tmp: Path, docs: bool = False) -> None:
        self.users, self.repo = MemoryUsers(), MemoryRepo()
        self.r = fakeredis.FakeRedis(decode_responses=True)
        self.users.create("alice", hash_password(PASSWORDS["alice"]), "analyst")
        self.users.create("root", hash_password(PASSWORDS["root"]), "admin")
        actions = Actions(self.r, self.repo, Notifier(None), load_policy())
        (tmp / "models" / "network").mkdir(parents=True)
        (tmp / "models" / "network" / "model_card.json").write_text(
            json.dumps({"model": "network-ids", "sample_size": 10, "dataset": {"name": "T"},
                        "metrics": {"x": 1}, "limitations": ["l"]}), encoding="utf-8")  # fmt: skip
        self.deps = Deps(SECRET, self.users, MemoryIncidents(self.repo), actions, self.repo,
                         self.r, models_dir=tmp / "models", docs=docs)  # fmt: skip
        self.client = TestClient(create_app(self.deps), raise_server_exceptions=False)

    def login(self, user: str) -> dict[str, str]:
        resp = self.client.post("/auth/token", json={"username": user, "password": PASSWORDS[user]})
        assert resp.status_code == 200, resp.text
        return {"Authorization": f"Bearer {resp.json()['access_token']}"}

    def add_incident(
        self, ip: str = "203.0.113.5", sev: str = "high", rule: str = "SEN-001"
    ) -> int:
        det = Detection(
            event_id="e",
            rule_id=rule,
            attack_id="T1110",
            severity=sev,  # type: ignore[arg-type]
            score=0.8,
            src_ip=ip,
            timestamp_event=1_700_000_000.0,
            explanation="x",
        )
        return self.repo.create_incident(det).incident_id


@pytest.fixture
def env(tmp_path: Path) -> Env:
    return Env(tmp_path)


# ------------------------------------------------------------------ passwords and tokens


def test_password_hashing() -> None:
    h = hash_password("correct horse battery")
    assert verify_password("correct horse battery", h) and not verify_password("wrong", h)
    assert h != hash_password("correct horse battery")  # random salt
    for junk in ("", "plain", "scrypt$1$2", "md5$a$b$c$d$e", "scrypt$x$y$z$!!$!!"):
        assert verify_password("anything", junk) is False
    with pytest.raises(ValueError):
        hash_password("short")


def test_token_roundtrip_and_rejections() -> None:
    tok = create_token("alice", SECRET, 5)
    assert decode_token(tok, SECRET)["sub"] == "alice"
    with pytest.raises(jwt.PyJWTError):
        decode_token(tok, "a-different-secret-" + "y" * 32)
    with pytest.raises(jwt.ExpiredSignatureError):
        decode_token(create_token("alice", SECRET, 5, now=time.time() - 3600), SECRET)
    with pytest.raises(ValueError):
        create_token("alice", "short", 5)


def test_forged_tokens_are_rejected(env: Env) -> None:
    now = int(time.time())
    claims = {"iss": ISSUER, "sub": "root", "iat": now, "exp": now + 600, "jti": "x"}
    forged = {
        "alg none": jwt.encode(claims, "", algorithm="none"),
        "other algorithm": jwt.encode(claims, SECRET, algorithm="HS512"),
        "wrong secret": jwt.encode(claims, "z" * 40, algorithm=ALGORITHM),
        "wrong issuer": jwt.encode({**claims, "iss": "evil"}, SECRET, algorithm=ALGORITHM),
        "missing jti": jwt.encode(
            {k: v for k, v in claims.items() if k != "jti"}, SECRET, algorithm=ALGORITHM
        ),  # fmt: skip
        "garbage": "not.a.jwt",
    }
    for name, token in forged.items():
        r = env.client.get("/incidents", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 401, name


def test_secret_must_be_strong(tmp_path: Path) -> None:
    e = Env(tmp_path)
    e.deps.jwt_secret = "short"  # noqa: S105
    with pytest.raises(RuntimeError, match="JWT_SECRET"):
        create_app(e.deps)


# ------------------------------------------------------------------ login


def test_login_success_and_failures(env: Env) -> None:
    ok = env.client.post("/auth/token", json={"username": "alice", "password": PASSWORDS["alice"]})
    assert (
        ok.status_code == 200 and ok.json()["role"] == "analyst" and ok.json()["expires_in"] == 1800
    )
    bad = env.client.post("/auth/token", json={"username": "alice", "password": "nope"})
    unknown = env.client.post("/auth/token", json={"username": "ghost", "password": "nope"})
    assert bad.status_code == unknown.status_code == 401
    assert bad.json() == unknown.json()  # no user enumeration through the message


def test_login_throttling(env: Env) -> None:
    for _ in range(5):
        assert (
            env.client.post("/auth/token", json={"username": "alice", "password": "x"}).status_code
            == 401
        )
    # even the correct password is refused now: the attacker cannot keep guessing
    r = env.client.post("/auth/token", json={"username": "alice", "password": PASSWORDS["alice"]})
    assert r.status_code == 429
    assert any(row["action"] == "login_failed" for row in env.repo.audit_rows)


@pytest.mark.parametrize(
    "username", ["' OR 1=1--", "admin'; DROP TABLE users;--", "a" * 64, "../../etc/passwd", "\x00"]
)
def test_login_with_hostile_username_is_a_clean_401(env: Env, username: str) -> None:
    r = env.client.post("/auth/token", json={"username": username, "password": "whatever-123456"})
    assert r.status_code == 401


def test_login_input_validation(env: Env) -> None:
    assert (
        env.client.post("/auth/token", json={"username": "a" * 5000, "password": "x"}).status_code
        == 422
    )
    assert env.client.post("/auth/token", json={"username": "a"}).status_code == 422
    assert (
        env.client.post(
            "/auth/token", content=b"{not json", headers={"content-type": "application/json"}
        ).status_code
        == 422
    )


# ------------------------------------------------------------------ authorisation


def test_public_and_protected_routes(env: Env) -> None:
    assert env.client.get("/health").json()["status"] == "ok"
    for path in ("/incidents", "/incidents/1", "/blocklist", "/rules", "/models"):
        assert env.client.get(path).status_code == 401, path
    assert env.client.get("/incidents", headers={"Authorization": "Basic abc"}).status_code == 401


def test_role_enforcement(env: Env) -> None:
    analyst, admin = env.login("alice"), env.login("root")
    body = {"ip": "203.0.113.50"}
    assert env.client.post("/blocklist", json=body, headers=analyst).status_code == 403
    assert env.client.post("/blocklist", json=body, headers=admin).status_code == 201
    assert env.client.get("/blocklist", headers=analyst).status_code == 200  # analyst can read
    assert env.client.get("/incidents", headers=admin).status_code == 200  # admin includes analyst


def test_revoked_and_disabled_users_lose_access_immediately(env: Env) -> None:
    headers = env.login("alice")
    assert env.client.get("/rules", headers=headers).status_code == 200
    env.users.users["alice"].disabled = True
    assert env.client.get("/rules", headers=headers).status_code == 401
    env.users.users["alice"].disabled = False
    env.users.users["alice"].role = "admin"  # role changes apply on the very next request
    assert (
        env.client.post("/blocklist", json={"ip": "203.0.113.51"}, headers=headers).status_code
        == 201
    )
    del env.users.users["alice"]
    assert env.client.get("/rules", headers=headers).status_code == 401


# ------------------------------------------------------------------ incidents


def test_incident_listing_filters_and_pagination(env: Env) -> None:
    h = env.login("alice")
    ids = [
        env.add_incident(ip=f"203.0.113.{i}", sev="high" if i % 2 else "low") for i in range(1, 8)
    ]
    all_rows = env.client.get("/incidents", headers=h).json()
    assert [r["id"] for r in all_rows] == sorted(ids, reverse=True)
    assert all(
        r["severity"] == "high"
        for r in env.client.get("/incidents?severity=high", headers=h).json()
    )
    page = env.client.get("/incidents?limit=3&offset=2", headers=h).json()
    assert [r["id"] for r in page] == sorted(ids, reverse=True)[2:5]
    for bad in ("limit=0", "limit=1000", "offset=-1", "status=nope", "severity=urgent"):
        assert env.client.get(f"/incidents?{bad}", headers=h).status_code == 422, bad


def test_incident_detail_and_status_update_is_audited(env: Env) -> None:
    h = env.login("alice")
    i = env.add_incident()
    assert env.client.get(f"/incidents/{i}", headers=h).json()["detector"] == "SEN-001"
    assert env.client.get("/incidents/999", headers=h).status_code == 404
    assert env.client.get("/incidents/abc", headers=h).status_code == 422
    assert (
        env.client.patch(f"/incidents/{i}", json={"status": "closed"}, headers=h).status_code == 200
    )
    assert env.client.get(f"/incidents/{i}", headers=h).json()["status"] == "closed"
    assert (
        env.client.patch(f"/incidents/{i}", json={"status": "deleted"}, headers=h).status_code
        == 422
    )
    assert env.client.patch("/incidents/999", json={"status": "open"}, headers=h).status_code == 404
    assert [r["actor"] for r in env.repo.audit_rows if r["action"] == "incident_status"] == [
        "api:alice"
    ]


# ------------------------------------------------------------------ blocklist and accounts


def test_blocklist_lifecycle(env: Env) -> None:
    analyst, admin = env.login("alice"), env.login("root")
    r = env.client.post(
        "/blocklist", json={"ip": "203.0.113.60", "ttl_seconds": 600, "reason": "t"}, headers=admin
    )
    assert r.status_code == 201 and r.json()["created"] is True
    again = env.client.post("/blocklist", json={"ip": "203.0.113.60"}, headers=admin)
    assert again.json()["created"] is False  # idempotent
    listing = env.client.get("/blocklist", headers=analyst).json()
    assert [(x["ip"], x["detector"]) for x in listing] == [("203.0.113.60", "manual:root")]
    assert 0 < listing[0]["ttl_seconds"] <= 600
    gone = env.client.delete("/blocklist/203.0.113.60", headers=analyst).json()
    assert gone == {"ip": "203.0.113.60", "removed": True}
    assert env.client.get("/blocklist", headers=analyst).json() == []
    actors = [(r["actor"], r["action"]) for r in env.repo.audit_rows]
    assert ("api:root", "block_ip") in actors and ("api:alice", "unblock_ip") in actors


def test_blocklist_input_validation(env: Env) -> None:
    admin, analyst = env.login("root"), env.login("alice")
    assert env.client.post("/blocklist", json={"ip": "127.0.0.1"}, headers=admin).status_code == 409
    for bad in ("not-an-ip", "1.2.3.4; FLUSHALL", "999.1.1.1", ""):
        assert env.client.post("/blocklist", json={"ip": bad}, headers=admin).status_code == 422, (
            bad
        )
    assert (
        env.client.post(
            "/blocklist", json={"ip": "203.0.113.1", "ttl_seconds": 10**9}, headers=admin
        ).status_code
        == 422
    )
    assert env.client.delete("/blocklist/not-an-ip", headers=analyst).status_code == 422
    assert env.client.delete("/blocklist/..%2f..%2fetc", headers=analyst).status_code in (404, 422)
    assert env.r.keys("sen:blocklist:*") == []


def test_unlock_account(env: Env) -> None:
    h = env.login("alice")
    env.r.set("sen:locked:bob", "x")
    env.repo.lock_account("bob", "x", None)
    assert env.client.post("/accounts/bob/unlock", headers=h).json() == {
        "username": "bob",
        "unlocked": True,
    }
    assert env.client.post("/accounts/bob/unlock", headers=h).json()["unlocked"] is False
    assert env.client.post("/accounts/b%20ob;x/unlock", headers=h).status_code == 422


# ------------------------------------------------------------------ rules, models, hardening


def test_rules_and_models(env: Env) -> None:
    h = env.login("alice")
    rules = env.client.get("/rules", headers=h).json()
    assert len(rules) >= 9 and {"id", "title", "attack_id", "severity", "actions"} <= set(rules[0])
    assert "condition" not in rules[0]  # detection logic is not exposed to analysts
    models = env.client.get("/models", headers=h).json()
    assert models[0]["name"] == "network-ids" and models[0]["dataset"] == "T"


def test_security_headers_and_no_docs_by_default(env: Env) -> None:
    r = env.client.get("/health")
    assert (
        r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    )
    assert (
        r.headers["cache-control"] == "no-store"
        and "default-src 'none'" in r.headers["content-security-policy"]
    )
    assert (
        env.client.get("/docs").status_code == 404
        and env.client.get("/openapi.json").status_code == 404
    )


def test_docs_can_be_enabled_for_development(tmp_path: Path) -> None:
    assert Env(tmp_path, docs=True).client.get("/docs").status_code == 200


def test_internal_errors_do_not_leak_details(env: Env) -> None:
    h = env.login("alice")

    def boom(*_a: object, **_k: object) -> list[dict[str, object]]:
        raise RuntimeError("secret internal detail: password=hunter2 at /srv/app.py")

    env.deps.incidents.list_incidents = boom  # type: ignore[method-assign]
    r = env.client.get("/incidents", headers=h)
    assert r.status_code == 500 and r.json() == {"detail": "internal error"}
    assert "hunter2" not in r.text
