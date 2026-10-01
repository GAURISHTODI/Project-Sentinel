"""Helpers for handling untrusted text (log fields, user input) safely."""

import re
from urllib.parse import unquote_plus

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def clean_text(value: object, limit: int = 120) -> str:
    """Printable, length-bounded rendering of untrusted data for logs, explanations and UIs."""
    text = _CONTROL.sub("?", str(value)).replace("\n", " ").replace("\r", " ")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def url_decode(value: str, rounds: int = 2) -> str:
    """Decode percent-encoding up to `rounds` times so double-encoded payloads cannot hide."""
    for _ in range(rounds):
        decoded = unquote_plus(value)
        if decoded == value:
            break
        value = decoded
    return value
