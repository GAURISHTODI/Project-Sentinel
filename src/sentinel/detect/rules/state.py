"""Window/novelty state for stateful rules. Redis in production, in-memory for tests and replay.

All windows use EVENT time (timestamp_generated), so replaying a recording gives the same
detections as live traffic.
"""

from __future__ import annotations

from typing import Protocol

import redis


class Store(Protocol):
    def record(self, key: str, ts: float, member: str, window: int) -> int:
        """Add `member` at `ts`; return how many distinct members fall in the last `window` s."""

    def claim(self, key: str, ts: float, cooldown: int) -> bool:
        """True if `key` has not fired in the last `cooldown` s (and mark it fired now)."""

    def novel(self, key: str, member: str, min_baseline: int) -> bool:
        """True if `member` is new for `key` after >= min_baseline PRIOR observations of `key`."""


class MemoryStore:
    def __init__(self) -> None:
        self._win: dict[str, dict[str, float]] = {}
        self._fired: dict[str, float] = {}
        self._sets: dict[str, set[str]] = {}
        self._obs: dict[str, int] = {}

    def record(self, key: str, ts: float, member: str, window: int) -> int:
        bucket = self._win.setdefault(key, {})
        bucket[member] = ts
        cutoff = ts - window
        for m in [m for m, t in bucket.items() if t <= cutoff]:
            del bucket[m]
        return len(bucket)

    def claim(self, key: str, ts: float, cooldown: int) -> bool:
        last = self._fired.get(key)
        if last is not None and ts - last < cooldown:
            return False
        self._fired[key] = ts
        return True

    def novel(self, key: str, member: str, min_baseline: int) -> bool:
        seen = self._sets.setdefault(key, set())
        prior = self._obs.get(key, 0)
        self._obs[key] = prior + 1
        is_novel = member not in seen and prior >= min_baseline
        seen.add(member)
        return is_novel


class RedisStore:
    """Sliding windows as sorted sets (score = event time), so counting is O(log n)."""

    def __init__(self, client: redis.Redis, prefix: str = "sen") -> None:
        self._r = client
        self._prefix = prefix

    def record(self, key: str, ts: float, member: str, window: int) -> int:
        k = f"{self._prefix}:win:{key}"
        pipe = self._r.pipeline()
        pipe.zadd(k, {member: ts})
        pipe.zremrangebyscore(k, "-inf", ts - window)
        pipe.zcard(k)
        pipe.expire(k, window + 60)
        return int(pipe.execute()[2])

    def claim(self, key: str, ts: float, cooldown: int) -> bool:
        k = f"{self._prefix}:fired:{key}"
        last = self._r.get(k)
        if last is not None and ts - float(str(last)) < cooldown:
            return False
        self._r.set(k, ts, ex=max(cooldown, 1) + 60)
        return True

    def novel(self, key: str, member: str, min_baseline: int) -> bool:
        k = f"{self._prefix}:seen:{key}"
        pipe = self._r.pipeline()
        pipe.incr(f"{k}:n")
        pipe.sadd(k, member)
        pipe.expire(f"{k}:n", 30 * 86400)
        pipe.expire(k, 30 * 86400)
        count, added = pipe.execute()[:2]
        return bool(added) and int(count) - 1 >= min_baseline
