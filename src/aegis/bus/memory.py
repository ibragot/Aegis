"""In-memory bus with Kafka-like semantics (topics, consumer groups, offsets)."""

from __future__ import annotations

import threading
from collections import defaultdict
from typing import Any

from aegis.bus.base import Message


class MemoryConsumer:
    def __init__(self, bus: MemoryBus, topics: list[str], group_id: str):
        self.bus, self.topics, self.group_id = bus, topics, group_id
        self._pending: dict[str, int] = {}

    def poll(self, timeout: float = 0.0, max_messages: int = 500) -> list[Message]:
        out: list[Message] = []
        with self.bus.lock:
            for topic in self.topics:
                log = self.bus.logs[topic]
                start = self._pending.get(topic, self.bus.offsets[(self.group_id, topic)])
                batch = log[start : start + max_messages - len(out)]
                out.extend(batch)
                self._pending[topic] = start + len(batch)
                if len(out) >= max_messages:
                    break
        return out

    def commit(self) -> None:
        with self.bus.lock:
            for topic, offset in self._pending.items():
                self.bus.offsets[(self.group_id, topic)] = offset

    def close(self) -> None:
        self.commit()

    def lag(self) -> int:
        with self.bus.lock:
            return sum(len(self.bus.logs[t]) - self.bus.offsets[(self.group_id, t)] for t in self.topics)


class MemoryBus:
    def __init__(self) -> None:
        self.logs: dict[str, list[Message]] = defaultdict(list)
        self.offsets: dict[tuple[str, str], int] = defaultdict(int)
        self.lock = threading.RLock()

    def publish(self, topic: str, value: dict[str, Any], key: str | None = None) -> None:
        with self.lock:
            log = self.logs[topic]
            log.append(Message(topic=topic, key=key, value=value, offset=len(log)))

    def flush(self) -> None:  # nothing buffered
        return None

    def consumer(self, topics: list[str], group_id: str) -> MemoryConsumer:
        return MemoryConsumer(self, topics, group_id)
