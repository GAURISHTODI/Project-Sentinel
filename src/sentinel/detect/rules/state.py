"""Window/novelty state for stateful rules. Redis in production, in-memory for tests and replay.

All windows use EVENT time (timestamp_generated), so replaying a recording gives the same
detections as live traffic.
"""

from __future__ import annotations

import time
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

    def apply(self, ops: list[tuple[str, str, float, str, int]]) -> None:
        """Replay queued CachedStore updates in a single pipelined round trip."""
        pipe = self._r.pipeline(transaction=False)
        for kind, key, ts, member, arg in ops:
            if kind == "r":
                k = f"{self._prefix}:win:{key}"
                pipe.zadd(k, {member: ts})
                pipe.zremrangebyscore(k, "-inf", ts - arg)
                pipe.expire(k, arg + 60)
            elif kind == "c":
                pipe.set(f"{self._prefix}:fired:{key}", ts, ex=max(arg, 1) + 60)
            else:
                k = f"{self._prefix}:seen:{key}"
                pipe.incr(f"{k}:n")
                pipe.sadd(k, member)
                pipe.expire(f"{k}:n", 30 * 86400)
                pipe.expire(k, 30 * 86400)
        pipe.execute()


class CachedStore:
    """Partition-local windows with batched write-behind to Redis.

    Why: a Redis round trip costs ~1 ms through Docker Desktop on Windows, and one per event caps
    the engine near 1,200 events/s. Kafka keys events by source IP, so one consumer sees every event
    of an IP and in-process windows are exact; Redis receives the same updates in one pipelined
    batch per flush, so state is durable and inspectable. Trade-off: after a restart the windows
    start empty (at most one window of history is lost); Redis is not read back.
    """

    def __init__(
        self, remote: RedisStore, flush_interval: float = 0.25, max_queue: int = 20_000
    ) -> None:
        self.local = MemoryStore()
        self._remote = remote
        self._interval, self._max = flush_interval, max_queue
        self._queue: list[tuple[str, str, float, str, int]] = []
        self._last_flush = time.monotonic()
        self.flush_errors = 0

    def _tick(self) -> None:
        if len(self._queue) >= self._max or time.monotonic() - self._last_flush >= self._interval:
            self.flush()

    def record(self, key: str, ts: float, member: str, window: int) -> int:
        n = self.local.record(key, ts, member, window)
        self._queue.append(("r", key, ts, member, window))
        self._tick()
        return n

    def claim(self, key: str, ts: float, cooldown: int) -> bool:
        ok = self.local.claim(key, ts, cooldown)
        if ok:
            self._queue.append(("c", key, ts, "", cooldown))
        return ok

    def novel(self, key: str, member: str, min_baseline: int) -> bool:
        is_novel = self.local.novel(key, member, min_baseline)
        self._queue.append(("n", key, 0.0, member, min_baseline))
        return is_novel

    def flush(self) -> None:
        """Push queued updates to Redis in one round trip. Redis trouble never stops detection."""
        self._last_flush = time.monotonic()
        if not self._queue:
            return
        batch, self._queue = self._queue, []
        try:
            self._remote.apply(batch)
        except redis.RedisError:
            self.flush_errors += 1  # local state stays authoritative; this batch is dropped
