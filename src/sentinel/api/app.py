"""Sentinel REST API: incidents, blocklist, rules, models. JWT auth with analyst/admin roles.

Security notes: tokens are HS256 with the algorithm pinned; the user's role is re-read from the
user store on every request (revoking or demoting someone takes effect immediately); logins are
throttled per source IP and per username; unknown-user and wrong-password take the same time;
internal errors never leak details; every state-changing call is written to the audit log.
"""

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any

import jwt
import redis
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from sentinel.api.security import (
    MIN_SECRET_LEN,
    create_token,
    decode_token,
    dummy_verify,
    verify_password,
)
from sentinel.api.store import IncidentReader, User, UserStore
from sentinel.common.logging import get_logger
from sentinel.common.security import clean_text
from sentinel.detect.rules.engine import DEFAULT_RULES_DIR, load_rules
from sentinel.respond.actions import BLOCK_PREFIX, Actions, valid_ip
from sentinel.respond.repo import Repository

log = get_logger(__name__)
ROLE_RANK = {"analyst": 1, "admin": 2}
USERNAME = re.compile(r"^[A-Za-z0-9_.@-]{1,64}$")
MAX_LOGIN_FAILURES = 5
LOGIN_WINDOW_S = 900
VERSION = "0.1.0"


@dataclass
class Deps:
    jwt_secret: str
    users: UserStore
    incidents: IncidentReader
    actions: Actions
    repo: Repository
    r: redis.Redis
    jwt_ttl_minutes: int = 30
    rules_dir: Path = DEFAULT_RULES_DIR
    models_dir: Path = Path("models")
    docs: bool = False


class LoginRequest(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105  # OAuth token type label, not a secret
    expires_in: int
    role: str


class StatusUpdate(BaseModel):
    status: str = Field(pattern=r"^(open|triaged|closed)$")


class BlockRequest(BaseModel):
    ip: str = Field(max_length=64)
    ttl_seconds: int = Field(default=3600, ge=1, le=86400)
    reason: str = Field(default="manual block", max_length=200)


def create_app(deps: Deps) -> FastAPI:
    if len(deps.jwt_secret) < MIN_SECRET_LEN:
        raise RuntimeError(f"JWT_SECRET must be at least {MIN_SECRET_LEN} characters")
    app = FastAPI(
        title="Sentinel API",
        version=VERSION,
        docs_url="/docs" if deps.docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if deps.docs else None,
    )
    bearer = HTTPBearer(auto_error=False)

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Any) -> Response:
        resp: Response = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        return resp

    @app.exception_handler(Exception)
    async def hide_internal_errors(request: Request, exc: Exception) -> JSONResponse:
        log.error(
            "unhandled error",
            extra={"fields": {"path": request.url.path, "error": clean_text(exc, 200)}},
        )
        return JSONResponse({"detail": "internal error"}, status_code=500)

    # ------------------------------------------------------------------ auth

    def current_user(
        creds: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    ) -> User:
        unauthorized = HTTPException(
            401, "invalid or missing credentials", headers={"WWW-Authenticate": "Bearer"}
        )
        if creds is None:
            raise unauthorized
        try:
            claims = decode_token(creds.credentials, deps.jwt_secret)
        except jwt.PyJWTError:
            raise unauthorized from None
        user = deps.users.get(str(claims["sub"]))
        if user is None or user.disabled:
            raise unauthorized
        return user

    def require(role: str) -> Any:
        def check(user: Annotated[User, Depends(current_user)]) -> User:
            if ROLE_RANK.get(user.role, 0) < ROLE_RANK[role]:
                raise HTTPException(403, "insufficient role")
            return user

        return check

    analyst = Depends(require("analyst"))
    admin = Depends(require("admin"))

    def audit(user: User, action: str, target: str | None, detail: dict[str, Any]) -> None:
        deps.repo.audit(f"api:{user.username}", action, target, detail)

    # ------------------------------------------------------------------ public

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": VERSION}

    @app.post("/auth/token", response_model=TokenResponse)
    def login(body: LoginRequest, request: Request) -> TokenResponse:
        ip = request.client.host if request.client else "unknown"
        keys = (f"sen:api:fail:ip:{ip}", f"sen:api:fail:user:{body.username[:64]}")
        if any(int(str(deps.r.get(k) or 0)) >= MAX_LOGIN_FAILURES for k in keys):
            raise HTTPException(429, "too many failed attempts, try again later")
        user = deps.users.get(body.username) if USERNAME.match(body.username) else None
        ok = False
        if user is not None and not user.disabled:
            ok = verify_password(body.password, user.password_hash)
        else:
            dummy_verify(body.password)  # same cost whether or not the user exists
        if not ok or user is None:
            for k in keys:
                pipe = deps.r.pipeline()
                pipe.incr(k)
                pipe.expire(k, LOGIN_WINDOW_S)
                pipe.execute()
            deps.repo.audit(
                "api:anonymous", "login_failed", clean_text(body.username, 64), {"ip": ip}
            )
            raise HTTPException(401, "invalid username or password")
        deps.r.delete(keys[1])
        token = create_token(user.username, deps.jwt_secret, deps.jwt_ttl_minutes, role=user.role)
        return TokenResponse(
            access_token=token, expires_in=deps.jwt_ttl_minutes * 60, role=user.role
        )

    # ------------------------------------------------------------------ incidents

    @app.get("/incidents")
    def list_incidents(
        _: Annotated[User, analyst],
        status: Annotated[str | None, Query(pattern=r"^(open|triaged|closed)$")] = None,
        severity: Annotated[str | None, Query(pattern=r"^(low|medium|high|critical)$")] = None,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
        offset: Annotated[int, Query(ge=0, le=100_000)] = 0,
    ) -> list[dict[str, Any]]:
        return deps.incidents.list_incidents(status, severity, limit, offset)

    @app.get("/incidents/{incident_id}")
    def get_incident(incident_id: int, _: Annotated[User, analyst]) -> dict[str, Any]:
        row = deps.incidents.get_incident(incident_id)
        if row is None:
            raise HTTPException(404, "incident not found")
        return row

    @app.patch("/incidents/{incident_id}")
    def update_incident(
        incident_id: int, body: StatusUpdate, user: Annotated[User, analyst]
    ) -> dict[str, Any]:
        if not deps.incidents.set_status(incident_id, body.status):
            raise HTTPException(404, "incident not found")
        audit(user, "incident_status", str(incident_id), {"status": body.status})
        return {"id": incident_id, "status": body.status}

    # ------------------------------------------------------------------ blocklist

    @app.get("/blocklist")
    def blocklist(_: Annotated[User, analyst]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for key in deps.r.scan_iter(f"{BLOCK_PREFIX}*", count=500):
            if len(out) >= 1000:
                break
            try:
                meta = json.loads(str(deps.r.get(key) or "{}"))
            except json.JSONDecodeError:
                meta = {}
            out.append(
                {
                    "ip": str(key).removeprefix(BLOCK_PREFIX),
                    "ttl_seconds": deps.r.ttl(key),
                    "detector": meta.get("detector"),
                    "since": meta.get("ts"),
                }
            )
        return sorted(out, key=lambda x: str(x["ip"]))

    @app.post("/blocklist", status_code=201)
    def add_block(body: BlockRequest, user: Annotated[User, admin]) -> dict[str, Any]:
        ip = valid_ip(body.ip)
        if ip is None:
            raise HTTPException(422, "not a valid IP address")
        if deps.actions.policy.is_protected(ip):
            raise HTTPException(409, "address is protected and cannot be blocked")
        meta = json.dumps(
            {"detector": f"manual:{user.username}", "reason": clean_text(body.reason, 200)}
        )
        created = bool(deps.r.set(BLOCK_PREFIX + ip, meta, nx=True, ex=body.ttl_seconds))
        audit(user, "block_ip", ip, {"ttl": body.ttl_seconds, "created": created, "manual": True})
        return {"ip": ip, "created": created, "ttl_seconds": body.ttl_seconds}

    @app.delete("/blocklist/{ip}")
    def unblock(ip: str, user: Annotated[User, analyst]) -> dict[str, Any]:
        clean = valid_ip(ip)
        if clean is None:
            raise HTTPException(422, "not a valid IP address")
        return {"ip": clean, "removed": deps.actions.unblock_ip(clean, f"api:{user.username}")}

    @app.post("/accounts/{username}/unlock")
    def unlock(username: str, user: Annotated[User, analyst]) -> dict[str, Any]:
        if not USERNAME.match(username):
            raise HTTPException(422, "invalid username")
        removed = deps.actions.unlock_account(username, f"api:{user.username}")
        return {"username": username, "unlocked": removed}

    # ------------------------------------------------------------------ rules and models

    @app.get("/rules")
    def rules(_: Annotated[User, analyst]) -> list[dict[str, Any]]:
        return [
            {
                "id": r.id,
                "title": r.title,
                "attack_id": r.attack_id,
                "severity": r.severity,
                "enabled": r.enabled,
                "actions": [a["action"] for a in r.response],
            }
            for r in load_rules(deps.rules_dir)
        ]

    @app.get("/models")
    def models(_: Annotated[User, analyst]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for card_path in sorted(deps.models_dir.glob("*/model_card.json")):
            try:
                card = json.loads(card_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            out.append(
                {
                    "name": card.get("model", card_path.parent.name),
                    "trained_at": card.get("trained_at"),
                    "sample_size": card.get("sample_size"),
                    "dataset": card.get("dataset", {}).get("name"),
                    "metrics": card.get("metrics"),
                    "limitations": card.get("limitations"),
                }
            )
        return out

    return app
