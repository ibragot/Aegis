"""Kafka implementation of the bus (confluent-kafka, the Python binding for librdkafka).

Key ideas implemented here (each is explained in the README):

* **Keyed partitioning** - `publish(key=entity)` hashes the key to a partition, so
  every event for one identity lands on the same partition, in order. That lets a
  stateful analyzer keep per-identity windows in memory safely.
* **Consumer groups** - `auth-analyzer-1` and `auth-analyzer-2` share the group id
  `auth-analyzer`; Kafka assigns each of them half of the partitions. Add replicas
  to scale out; if one dies its partitions are rebalanced to the survivor.
* **At-least-once delivery** - auto-commit is disabled; offsets are committed only
  after a batch has been fully processed. A crash means re-processing, never loss,
  which is why downstream writes are idempotent (deterministic ids + upserts).
* **Idempotent producer + acks=all** - no duplicates from producer retries and a
  write is only acknowledged once all in-sync replicas have it.
* **Trace propagation** - the W3C `traceparent` header is injected into every
  message so one trace spans collector -> analyzer -> correlator -> investigator.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from aegis.bus.base import ALL_TOPICS, Message
from aegis.config import Settings
from aegis.observability import metrics, tracing

log = logging.getLogger(__name__)


def _common(settings: Settings) -> dict[str, Any]:
    conf: dict[str, Any] = {"bootstrap.servers": settings.kafka_bootstrap}
    if settings.kafka_security_protocol != "PLAINTEXT":
        # Amazon MSK with IAM auth or TLS - see deploy/terraform/msk.tf
        conf["security.protocol"] = settings.kafka_security_protocol
    return conf


class KafkaConsumer:
    def __init__(self, settings: Settings, topics: list[str], group_id: str):
        from confluent_kafka import Consumer

        self.group_id = group_id
        self._consumer = Consumer(
            {
                **_common(settings),
                "group.id": group_id,
                "enable.auto.commit": False,
                "auto.offset.reset": "earliest",
                "partition.assignment.strategy": "cooperative-sticky",
                "session.timeout.ms": 15000,
            }
        )
        self._consumer.subscribe(topics)
        self._last_lag_report = 0.0

    def poll(self, timeout: float = 1.0, max_messages: int = 500) -> list[Message]:
        raw = self._consumer.consume(num_messages=max_messages, timeout=timeout)
        out = []
        for m in raw:
            if m.error():
                log.warning("kafka error: %s", m.error())
                continue
            headers = {k: v.decode() for k, v in (m.headers() or [])}
            out.append(
                Message(
                    topic=m.topic(),
                    key=m.key().decode() if m.key() else None,
                    value=json.loads(m.value()),
                    headers=headers,
                    partition=m.partition(),
                    offset=m.offset(),
                )
            )
        self._maybe_report_lag()
        return out

    def _maybe_report_lag(self) -> None:
        """Consumer lag = newest offset in the partition - our committed position."""
        now = time.monotonic()
        if now - self._last_lag_report < 15:
            return
        self._last_lag_report = now
        try:
            for tp in self._consumer.assignment():
                low, high = self._consumer.get_watermark_offsets(tp, timeout=1, cached=False)
                pos = self._consumer.position([tp])[0].offset
                lag = high - pos if pos >= 0 else high - low
                metrics.CONSUMER_LAG.labels(self.group_id, tp.topic, str(tp.partition)).set(max(lag, 0))
        except Exception as exc:  # metrics must never break processing
            log.debug("lag report failed: %s", exc)

    def commit(self) -> None:
        from confluent_kafka import KafkaException

        try:
            self._consumer.commit(asynchronous=False)
        except KafkaException as exc:  # nothing to commit yet is not an error
            log.debug("commit: %s", exc)

    def close(self) -> None:
        self._consumer.close()


class KafkaBus:
    def __init__(self, settings: Settings):
        from confluent_kafka import Producer

        self.settings = settings
        self._producer = Producer(
            {
                **_common(settings),
                "enable.idempotence": True,
                "acks": "all",
                "compression.type": "lz4",
                "linger.ms": 20,
            }
        )
        self._ensure_topics()

    def _ensure_topics(self) -> None:
        from confluent_kafka.admin import AdminClient, NewTopic

        admin = AdminClient(_common(self.settings))
        for attempt in range(30):
            try:
                existing = set(admin.list_topics(timeout=5).topics)
                break
            except Exception as exc:
                log.info("waiting for kafka (%s): %s", attempt, exc)
                time.sleep(2)
        else:
            raise RuntimeError("Kafka not reachable")
        missing = [
            NewTopic(t, num_partitions=self.settings.kafka_partitions,
                     replication_factor=self.settings.kafka_replication)
            for t in ALL_TOPICS if t not in existing
        ]
        if missing:
            for topic, fut in admin.create_topics(missing).items():
                try:
                    fut.result()
                    log.info("created topic %s", topic)
                except Exception as exc:  # raced with another service - fine
                    log.debug("topic %s: %s", topic, exc)

    def publish(self, topic: str, value: dict[str, Any], key: str | None = None) -> None:
        headers = tracing.inject_headers()
        while True:
            try:
                self._producer.produce(
                    topic,
                    json.dumps(value, default=str).encode(),
                    key=key.encode() if key else None,
                    headers=list(headers.items()),
                )
                break
            except BufferError:  # local queue full - let librdkafka drain it
                self._producer.poll(0.5)
        self._producer.poll(0)

    def flush(self) -> None:
        self._producer.flush(10)

    def consumer(self, topics: list[str], group_id: str) -> KafkaConsumer:
        return KafkaConsumer(self.settings, topics, group_id)
