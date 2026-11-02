"""Event bus abstraction.

Services never import Kafka directly - they talk to a `Bus`. Two
implementations exist:

* `MemoryBus` - a list per topic + an offset per consumer group. Used by the
  one-process demo and the tests, so you can learn the whole pipeline without
  running any infrastructure.
* `KafkaBus`  - the real thing (confluent-kafka / librdkafka): keyed
  partitioning, consumer groups, manual offset commits (at-least-once),
  OpenTelemetry context propagated through message headers.
"""

from __future__ import annotations

from aegis.bus.base import Bus, Consumer, Message
from aegis.bus.memory import MemoryBus
from aegis.config import Settings, get_settings

__all__ = ["Bus", "Consumer", "Message", "MemoryBus", "create_bus"]


def create_bus(settings: Settings | None = None) -> Bus:
    settings = settings or get_settings()
    if settings.bus == "kafka":
        from aegis.bus.kafka import KafkaBus

        return KafkaBus(settings)
    return MemoryBus()
