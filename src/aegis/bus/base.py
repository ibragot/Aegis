from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

# --------------------------------------------------------------------------- topics
# raw.*     : untouched source logs, produced by log shippers / the simulator
# events.*  : normalized Events, routed by category so each analyzer only reads what it needs
# alerts    : output of the rules engine and the ML engine
# incidents : correlated incidents (output of the detection engine / correlator)
RAW_TOPICS = {
    "cloudtrail": "raw.cloudtrail",
    "auth": "raw.auth",
    "k8s_audit": "raw.k8s",
    "network": "raw.network",
    "app": "raw.app",
}
EVENTS_AUTH = "events.auth"
EVENTS_CLOUD = "events.cloud"
EVENTS_NETWORK = "events.network"
EVENT_TOPICS = [EVENTS_AUTH, EVENTS_CLOUD, EVENTS_NETWORK]
ALERTS = "alerts"
INCIDENTS = "incidents"
DEAD_LETTER = "deadletter"
ALL_TOPICS = [*RAW_TOPICS.values(), *EVENT_TOPICS, ALERTS, INCIDENTS, DEAD_LETTER]

_CATEGORY_TOPIC = {
    "authentication": EVENTS_AUTH,
    "iam": EVENTS_CLOUD,
    "resource": EVENTS_CLOUD,
    "api": EVENTS_CLOUD,
    "kubernetes": EVENTS_CLOUD,
    "network": EVENTS_NETWORK,
    "application": EVENTS_NETWORK,
}


def topic_for_category(category: str) -> str:
    return _CATEGORY_TOPIC[category]


@dataclass
class Message:
    topic: str
    key: str | None
    value: dict[str, Any]
    headers: dict[str, str] = field(default_factory=dict)
    partition: int = 0
    offset: int = 0


class Consumer(Protocol):
    def poll(self, timeout: float = 1.0, max_messages: int = 500) -> list[Message]: ...

    def commit(self) -> None: ...

    def close(self) -> None: ...


class Bus(Protocol):
    def publish(self, topic: str, value: dict[str, Any], key: str | None = None) -> None: ...

    def flush(self) -> None: ...

    def consumer(self, topics: list[str], group_id: str) -> Consumer: ...
