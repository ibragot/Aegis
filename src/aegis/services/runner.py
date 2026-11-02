"""Run one processor as a long-lived Kafka consumer service.

    poll batch -> process -> publish outputs -> flush producer -> commit offsets

Committing *after* the outputs are flushed gives at-least-once semantics: if
the process crashes mid-batch, the batch is re-read on restart. Deterministic
ids + upserts make the re-processing harmless.
"""

from __future__ import annotations

import heapq
import logging
import random
import signal
import threading
import time
from datetime import UTC, datetime

from aegis.bus import create_bus
from aegis.bus.base import RAW_TOPICS
from aegis.config import Settings, get_settings
from aegis.observability import metrics, setup_logging, tracing
from aegis.services.processors import (
    AnalyzerProcessor,
    CollectorProcessor,
    CorrelatorProcessor,
    IndexerProcessor,
    InvestigatorProcessor,
    MLProcessor,
    Processor,
)
from aegis.state import create_state_store

log = logging.getLogger(__name__)


def build_processor(service: str, settings: Settings) -> Processor:
    state = create_state_store(settings.redis_url)
    if service == "collector":
        from aegis.storage.archive import Archiver

        return CollectorProcessor(Archiver(settings))
    if service in ("auth-analyzer", "cloud-analyzer", "network-analyzer"):
        return AnalyzerProcessor(service.split("-")[0], settings, state)
    if service == "ml-inference":
        return MLProcessor(state=state)
    from aegis.storage.db import create_repository

    repo = create_repository(settings.database_url)
    if service == "indexer":
        return IndexerProcessor(repo)
    if service == "correlator":
        return CorrelatorProcessor(repo, settings)
    if service == "investigator":
        from aegis.investigator import Investigator

        return InvestigatorProcessor(Investigator(repo, settings))
    raise SystemExit(f"unknown service {service}")


def _install_stop(stop: threading.Event) -> None:
    def handler(*_):
        log.info("shutdown requested")
        stop.set()

    signal.signal(signal.SIGTERM, handler)  # Kubernetes sends SIGTERM before killing a pod
    signal.signal(signal.SIGINT, handler)


def run_service(service: str) -> None:
    settings = get_settings()
    setup_logging(settings.log_level, json_logs=settings.bus == "kafka")
    tracing.setup_tracing(f"aegis-{service}", settings.otel_endpoint)
    metrics.serve(settings.metrics_port)
    stop = threading.Event()
    _install_stop(stop)

    if service == "generator":
        return run_generator(settings, stop)

    bus = create_bus(settings)
    proc = build_processor(service, settings)
    consumer = bus.consumer(proc.topics, proc.group)
    log.info("%s consuming %s as group %s", service, proc.topics, proc.group)
    while not stop.is_set():
        messages = consumer.poll(timeout=1.0, max_messages=500)
        outputs = []
        if messages:
            t = time.perf_counter()
            with tracing.span_from_headers(f"{service}.process", messages[0].headers, batch_size=len(messages)):
                try:
                    outputs = proc.handle(messages)
                except Exception:
                    log.exception("batch failed")
                    metrics.PROCESSING_ERRORS.labels(service).inc()
                    time.sleep(1)
                    continue  # do NOT commit: the batch will be retried
                for topic, key, value in outputs:
                    bus.publish(topic, value, key=key)
            for m in messages:
                metrics.EVENTS_PROCESSED.labels(service, m.topic).inc()
            metrics.PROCESSING_SECONDS.labels(service).observe(time.perf_counter() - t)
        for topic, key, value in proc.maybe_tick():
            bus.publish(topic, value, key=key)
        bus.flush()
        if messages:
            consumer.commit()
    proc.maybe_tick(force=True)
    consumer.close()


def run_generator(settings: Settings, stop: threading.Event) -> None:
    """Continuously emit benign telemetry, and inject an attack scenario every N seconds.

    Records are scheduled on a heap by their event time and published when due, so
    an injected scenario unfolds over ~8 minutes just like a real intrusion would.
    """
    from aegis.simulator import SCENARIOS, BaselineSimulator, event_time, run_scenario

    bus = create_bus(settings)
    sim = BaselineSimulator(settings.seed)
    rng = random.Random(settings.seed)
    heap: list[tuple[float, int, dict]] = []
    seq = 0
    next_attack = time.time() + 60
    log.info("generator: %.1f activities/s, attack every %ss", settings.generator_rate, settings.attack_interval_seconds)

    def schedule(envs: list[dict]) -> None:
        nonlocal seq
        for env in envs:
            seq += 1
            heapq.heappush(heap, (event_time(env).timestamp(), seq, env))

    while not stop.is_set():
        now = time.time()
        schedule(sim.random_activity(datetime.now(UTC)))
        if now >= next_attack:
            name = rng.choice(list(SCENARIOS))
            log.info("injecting attack scenario %s", name)
            schedule(run_scenario(name, datetime.now(UTC), seed=rng.randint(0, 10**6)))
            next_attack = now + settings.attack_interval_seconds
        while heap and heap[0][0] <= now:
            _, _, env = heapq.heappop(heap)
            bus.publish(RAW_TOPICS[env["source"]], env, key=None)
            metrics.EVENTS_PROCESSED.labels("generator", RAW_TOPICS[env["source"]]).inc()
        bus.flush()
        stop.wait(1.0 / max(settings.generator_rate, 0.1))
