"""Deterministic multi-source event generator: benign traffic plus interleaved attack campaigns."""

from __future__ import annotations

import random
from collections.abc import Iterator

from sentinel.common.schema import NormalizedEvent
from sentinel.generator.scenarios import ATTACKS, World, benign_event

# Campaign sizes differ by 100x (a port scan is hundreds of events, a service install is one), so
# campaigns are weighted to give every scenario a usable number of labeled events.
DEFAULT_MIX: dict[str, float] = {
    "brute_force": 1.0,
    "credential_stuffing": 1.0,
    "sqli": 2.0,
    "xss": 2.0,
    "path_traversal": 2.0,
    "scanner": 3.0,
    "port_scan": 0.5,
    "dos": 0.4,
    "valid_account_abuse": 6.0,
    "endpoint_powershell": 8.0,
    "endpoint_spawn": 8.0,
    "endpoint_service": 30.0,
}


def parse_mix(spec: str | None) -> dict[str, float]:
    """'sqli=3,brute_force=1' -> weights. None or empty uses DEFAULT_MIX."""
    if not spec:
        return dict(DEFAULT_MIX)
    mix: dict[str, float] = {}
    for part in spec.split(","):
        name, _, weight = part.partition("=")
        name = name.strip()
        if name not in ATTACKS:
            raise ValueError(f"unknown scenario {name!r}; choose from {sorted(ATTACKS)}")
        mix[name] = float(weight) if weight else 1.0
    return mix


class Generator:
    def __init__(
        self,
        eps: int,
        duration: int,
        seed: int = 42,
        attack_ratio: float = 0.10,
        mix: dict[str, float] | None = None,
        concurrent: int = 3,
    ) -> None:
        if eps < 1 or duration < 1 or not 0.0 <= attack_ratio < 1.0:
            raise ValueError("need eps>=1, duration>=1 and 0<=attack_ratio<1")
        self.eps, self.duration, self.attack_ratio = eps, duration, attack_ratio
        self.rng = random.Random(seed)
        self.world = World(seed=seed)
        self.mix = mix or dict(DEFAULT_MIX)
        self.concurrent = concurrent
        self._active: list[Iterator[NormalizedEvent]] = []

    def _next_attack(self, slot: int) -> NormalizedEvent:
        while True:
            while len(self._active) < self.concurrent:
                name = self.rng.choices(list(self.mix), weights=list(self.mix.values()))[0]
                self._active.append(ATTACKS[name](self.rng, self.world))
            i = slot % len(self._active)
            try:
                return next(self._active[i])
            except StopIteration:
                self._active.pop(i)

    def batches(self, start_ts: float) -> Iterator[tuple[int, list[NormalizedEvent]]]:
        """Yield (second_index, events) so a runner can pace emission in real time."""
        for sec in range(self.duration):
            n_attack = round(self.eps * self.attack_ratio)
            kinds = [True] * n_attack + [False] * (self.eps - n_attack)
            self.rng.shuffle(kinds)
            batch: list[NormalizedEvent] = []
            for i, is_attack in enumerate(kinds):
                ev = self._next_attack(i) if is_attack else benign_event(self.rng, self.world)
                ev.timestamp_generated = start_ts + sec + i / self.eps
                batch.append(ev)
            yield sec, batch

    def stream(self, start_ts: float = 1_700_000_000.0) -> Iterator[NormalizedEvent]:
        for _, batch in self.batches(start_ts):
            yield from batch
