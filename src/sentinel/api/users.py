"""Create API users: python -m sentinel.api.users create <username> <analyst|admin>.

The password comes from the SENTINEL_NEW_PASSWORD environment variable or a prompt, never a
command-line argument (arguments leak into shell history and process lists).
"""

from __future__ import annotations

import argparse
import getpass
import os
import re
import sys

from sentinel.api.security import hash_password
from sentinel.api.store import ROLES, PgUsers
from sentinel.common.config import dsn_for, get_settings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Manage Sentinel API users")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create")
    c.add_argument("username")
    c.add_argument("role", choices=ROLES)
    a = ap.parse_args(argv)
    if not re.match(r"^[A-Za-z0-9_.@-]{1,64}$", a.username):
        print("invalid username", file=sys.stderr)
        return 2
    password = os.environ.get("SENTINEL_NEW_PASSWORD") or getpass.getpass("password (12+ chars): ")
    users = PgUsers(dsn_for(get_settings(), "api"))
    users.create(a.username, hash_password(password), a.role)
    users.close()
    print(f"created {a.role} {a.username}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
