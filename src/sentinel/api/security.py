"""Password hashing (stdlib scrypt) and JWT helpers. No third-party crypto beyond PyJWT."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import time
import uuid
from typing import Any

import jwt

ISSUER = "sentinel"
ALGORITHM = "HS256"  # pinned on decode: tokens naming any other algorithm are rejected
MIN_SECRET_LEN = 32
_N, _R, _P = 2**14, 8, 1
# Verified against when the user does not exist: unknown-user and wrong-password cost the same.
_DUMMY = ""


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("password must be at least 12 characters")
    salt = os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=_N, r=_R, p=_P, dklen=32)
    return (
        f"scrypt${_N}${_R}${_P}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_b64, dk_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        salt, expected = base64.b64decode(salt_b64), base64.b64decode(dk_b64)
        dk = hashlib.scrypt(
            password.encode(), salt=salt, n=int(n), r=int(r), p=int(p), dklen=len(expected)
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk, expected)


def dummy_verify(password: str) -> None:
    global _DUMMY
    if not _DUMMY:
        _DUMMY = hash_password("not-a-real-password-for-timing")
    verify_password(password, _DUMMY)


def create_token(username: str, secret: str, ttl_minutes: int, now: float | None = None) -> str:
    if len(secret) < MIN_SECRET_LEN:
        raise ValueError("JWT secret too short")
    t = int(now if now is not None else time.time())
    claims = {
        "iss": ISSUER,
        "sub": username,
        "iat": t,
        "exp": t + ttl_minutes * 60,
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(claims, secret, algorithm=ALGORITHM)


def decode_token(token: str, secret: str) -> dict[str, Any]:
    """Raises jwt.PyJWTError on any problem (expired, bad signature, wrong algorithm, claims)."""
    return dict(
        jwt.decode(
            token,
            secret,
            algorithms=[ALGORITHM],
            issuer=ISSUER,
            options={"require": ["exp", "iat", "sub", "iss", "jti"]},
        )
    )
