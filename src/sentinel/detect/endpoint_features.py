"""Endpoint anomaly features: command-line entropy and parent/child process rarity.

These are derived facts computed from untrusted endpoint fields (command_line, process_name,
parent_process) and made available to the rule engine alongside the event's own fields (see
`sentinel.detect.rules.engine.build_facts`). They do not themselves decide anything; a rule can
reference them (e.g. `cmdline_entropy|gt: 4.5`) the same way it references any other fact.

Rarity uses the same novelty mechanism as SEN-006 (`Store.novel`), so it needs no new state backend:
a (parent, child) pair is "rare" once the parent has been observed with at least `min_baseline`
prior children and this particular child is new to it.
"""

from __future__ import annotations

import math
from collections import Counter

MAX_ENTROPY_INPUT = 8192  # untrusted input: never compute over an unbounded command line


def command_line_entropy(command_line: str | None) -> float | None:
    """Shannon entropy in bits/character; None for empty input (not zero: not comparable)."""
    if not command_line:
        return None
    text = command_line[:MAX_ENTROPY_INPUT]
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())
