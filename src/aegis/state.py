"""State store for stateful detections (sliding windows, "first seen" sets, cooldowns).

Why this matters: a rule like "5 failed logins in 5 minutes" needs memory. If
two analyzer replicas each keep their own memory, and failures for one user
are split between them, neither replica ever sees 5. Two fixes exist:

1. Partition by the rule's group-by key (Kafka keying), so one replica owns
   each key - that is what we do for per-principal rules, OR
2. Keep the state in a shared store - Redis - which is what `RedisStateStore`
   does. It also survives restarts / redeployments.

Windows are implemented with sorted sets: score = timestamp, member = event id
(for counts) or the value itself (for distinct counts).
"""

from __future__ import annotations

import bisect
from collections import defaultdict
from typing import Protocol


class StateStore(Protocol):
    def window_add(self, key: str, ts: float, member: str, window: float) -> None: ...

    def window_count(self, key: str, since: float) -> int: ...

    def window_members(self, key: str, since: float) -> list[str]: ...

    def seen_add(self, key: str, value: str) -> bool:
        """Add value to the set; return True if it was NEW."""
        ...

    def seen_size(self, key: str) -> int: ...

    def cooldown(self, key: str, ts: float, seconds: float) -> bool:
        """Return True if an action may fire now (and start the cooldown)."""
        ...


class MemoryStateStore:
    def __init__(self) -> None:
        self._windows: dict[str, dict[str, float]] = defaultdict(dict)
        self._sets: dict[str, set[str]] = defaultdict(set)
        self._cooldowns: dict[str, float] = {}

    def window_add(self, key: str, ts: float, member: str, window: float) -> None:
        w = self._windows[key]
        w[member] = max(ts, w.get(member, ts))
        if len(w) > 2000:  # prune old members to bound memory
            cutoff = ts - window
            for m in [m for m, t in w.items() if t < cutoff]:
                del w[m]

    def window_count(self, key: str, since: float) -> int:
        return sum(1 for t in self._windows[key].values() if t >= since)

    def window_members(self, key: str, since: float) -> list[str]:
        items = sorted((t, m) for m, t in self._windows[key].items())
        idx = bisect.bisect_left(items, (since, ""))
        return [m for _, m in items[idx:]]

    def seen_add(self, key: str, value: str) -> bool:
        s = self._sets[key]
        if value in s:
            return False
        s.add(value)
        return True

    def seen_size(self, key: str) -> int:
        return len(self._sets[key])

    def cooldown(self, key: str, ts: float, seconds: float) -> bool:
        # Event-time based and tolerant of out-of-order events: suppress only if
        # another alert fired within +/- `seconds` of this event's timestamp.
        last = self._cooldowns.get(key)
        if last is not None and abs(ts - last) < seconds:
            return False
        self._cooldowns[key] = ts
        return True


class RedisStateStore:
    def __init__(self, url: str, namespace: str = "aegis"):
        import redis

        self.r = redis.Redis.from_url(url, decode_responses=True)
        self.ns = namespace

    def _k(self, kind: str, key: str) -> str:
        return f"{self.ns}:{kind}:{key}"

    def window_add(self, key: str, ts: float, member: str, window: float) -> None:
        k = self._k("win", key)
        pipe = self.r.pipeline()
        pipe.zadd(k, {member: ts})
        pipe.zremrangebyscore(k, "-inf", ts - window)
        pipe.expire(k, int(window * 2) + 60)
        pipe.execute()

    def window_count(self, key: str, since: float) -> int:
        return int(self.r.zcount(self._k("win", key), since, "+inf"))

    def window_members(self, key: str, since: float) -> list[str]:
        return list(self.r.zrangebyscore(self._k("win", key), since, "+inf"))

    def seen_add(self, key: str, value: str) -> bool:
        return bool(self.r.sadd(self._k("seen", key), value))

    def seen_size(self, key: str) -> int:
        return int(self.r.scard(self._k("seen", key)))

    def cooldown(self, key: str, ts: float, seconds: float) -> bool:
        # SET NX EX is atomic, so two replicas can't both fire the same alert.
        return bool(self.r.set(self._k("cd", key), str(ts), nx=True, ex=max(1, int(seconds))))


def create_state_store(redis_url: str | None) -> StateStore:
    if redis_url:
        return RedisStateStore(redis_url)
    return MemoryStateStore()
