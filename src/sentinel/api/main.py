"""Run the API: python -m sentinel.api.main  (binds to 127.0.0.1 unless API_HOST says otherwise)."""

from __future__ import annotations

import os

import redis
import uvicorn
from fastapi import FastAPI

from sentinel.api.app import Deps, create_app
from sentinel.api.store import PgIncidents, PgUsers
from sentinel.common.config import get_settings
from sentinel.respond.actions import Actions
from sentinel.respond.notify import Notifier
from sentinel.respond.policy import load_policy
from sentinel.respond.repo import PgRepo


def build_app() -> FastAPI:
    cfg = get_settings()
    dsn = cfg.database_url.get_secret_value()
    r = redis.Redis.from_url(cfg.redis_url.get_secret_value(), decode_responses=True)
    repo = PgRepo(dsn)
    policy = load_policy()
    notifier = Notifier(cfg.webhook_url.get_secret_value() or None, cfg.webhook_flavor)
    return create_app(
        Deps(
            jwt_secret=cfg.jwt_secret.get_secret_value(),
            users=PgUsers(dsn),
            incidents=PgIncidents(dsn),
            actions=Actions(r, repo, notifier, policy),
            repo=repo,
            r=r,
            jwt_ttl_minutes=cfg.jwt_ttl_minutes,
            docs=cfg.api_docs,
        )
    )


def main() -> int:
    uvicorn.run(
        build_app(),
        host=os.environ.get("API_HOST", "127.0.0.1"),
        port=int(os.environ.get("API_PORT", "8080")),
        log_level="info",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
