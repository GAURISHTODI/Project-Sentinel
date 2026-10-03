"""Turns untrusted event fields into delimited, length-capped data for the LLM prompt.

Every field here came from a remote client (user agent, path, username, command line). It is
treated as data only: control characters are removed, the value is length-capped, and it is
wrapped in a delimiter with a random per-call nonce so text inside a field cannot close its own
delimiter. Injection-like phrases are counted for the audit log; they are not blocked, because
blocking them would hide evidence from the analyst.
"""

from __future__ import annotations

import re
import secrets

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f‪-‮⁦-⁩]")
_INJECTION_HINTS = re.compile(
    r"ignore (all |the )?(previous|prior|above) (instructions|prompts?)"
    r"|disregard (the )?(system|previous) (prompt|instructions)"
    r"|you are now|new instructions|system prompt|</?(system|assistant|user)>"
    r"|act as|jailbreak|developer mode|override (the )?(policy|rules)",
    re.IGNORECASE,
)
MAX_FIELD_CHARS = 300


def clean(value: object, limit: int = MAX_FIELD_CHARS) -> str:
    text = _CONTROL.sub("?", str(value))[:limit]
    return text


def delimit_fields(fields: dict[str, object]) -> tuple[str, dict[str, int]]:
    """Render untrusted fields as nonce-delimited blocks. Returns the block text and hint counts."""
    nonce = secrets.token_hex(8)
    blocks: list[str] = []
    hints: dict[str, int] = {}
    for name, value in fields.items():
        text = clean(value) if value is not None else ""
        hints[name] = len(_INJECTION_HINTS.findall(text))
        blocks.append(
            f"<untrusted field={name!r} nonce={nonce}>\n{text}\n</untrusted nonce={nonce}>"
        )
    return "\n".join(blocks), hints
