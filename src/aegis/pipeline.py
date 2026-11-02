"""The whole Aegis pipeline in one process (no Kafka, no Postgres required).

Used by `aegis demo`, by the API in local mode, and by the tests. It wires the
same processors the microservices use onto a `MemoryBus` and pumps messages
stage by stage until everything is processed.
"""

from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime, timedelta

from aegis.bus.base import RAW_TOPICS
from aegis.bus.memory import MemoryBus
from aegis.config import Settings, get_settings
from aegis.services.processors import (
    AnalyzerProcessor,
    CollectorProcessor,
    CorrelatorProcessor,
    IndexerProcessor,
    InvestigatorProcessor,
    MLProcessor,
    Processor,
)
from aegis.state import MemoryStateStore
from aegis.storage.db import Repository

log = logging.getLogger(__name__)


class LocalPipeline:
    def __init__(self, settings: Settings | None = None, repo: Repository | None = None, use_ml: bool = True,
                 use_llm: bool = False, ml_engine=None):
        self.settings = settings or get_settings()
        self.repo = repo or Repository(self.settings.database_url)
        self.use_llm = use_llm
        self.bus = MemoryBus()
        self.lock = threading.RLock()
        from aegis.investigator import Investigator

        self.investigator = Investigator(self.repo, self.settings)
        state = MemoryStateStore()
        stages: list[Processor] = [CollectorProcessor(), IndexerProcessor(self.repo)]
        stages += [AnalyzerProcessor(k, self.settings, state) for k in ("auth", "cloud", "network")]
        if use_ml:
            stages.append(MLProcessor(engine=ml_engine, state=state))
        self.correlator = CorrelatorProcessor(self.repo, self.settings)
        stages += [self.correlator, InvestigatorProcessor(self.investigator, debounce_s=0, use_llm=use_llm)]
        self.stages = stages
        self.consumers = {p.name: self.bus.consumer(p.topics, p.group) for p in stages}

    def ingest(self, envelopes: list[dict]) -> None:
        with self.lock:
            for env in envelopes:
                self.bus.publish(RAW_TOPICS[env["source"]], env)

    def process(self, envelopes: list[dict], chunk: int = 400) -> int:
        """Ingest in small time-ordered chunks and drain the pipeline after each one.

        Draining a whole day at once would hand stateful consumers (ML profiles,
        rule windows) batches that jump back and forth in time.
        """
        total = 0
        for i in range(0, len(envelopes), chunk):
            self.ingest(envelopes[i : i + chunk])
            total += self.run_until_idle()
        return total

    def run_until_idle(self, max_rounds: int = 50) -> int:
        """Pump all stages in order until no stage has pending messages."""
        processed = 0
        with self.lock:
            for _ in range(max_rounds):
                moved = 0
                for proc in self.stages:
                    if proc is self.stages[-1]:
                        # merge late-linked incidents before investigating
                        for topic, key, value in self.correlator.maybe_tick(force=True):
                            self.bus.publish(topic, value, key=key)
                    consumer = self.consumers[proc.name]
                    while True:
                        msgs = consumer.poll(max_messages=2000)
                        if not msgs:
                            break
                        for topic, key, value in proc.handle(msgs):
                            self.bus.publish(topic, value, key=key)
                        consumer.commit()
                        moved += len(msgs)
                processed += moved
                if moved == 0:
                    break
        return processed

    def simulate(self, scenario: str, start: datetime | None = None, seed: int | None = None,
                 with_baseline_minutes: int = 0) -> int:
        from aegis.simulator import BaselineSimulator, event_time, run_scenario

        start = start or datetime.now(UTC)
        envs = run_scenario(scenario, start, seed=seed)
        if with_baseline_minutes:
            sim = BaselineSimulator(seed or 0)
            envs += list(sim.generate(start - timedelta(minutes=5), hours=with_baseline_minutes / 60))
            envs.sort(key=event_time)
        return self.process(envs)

    def warm_up(self, days: float = 2, seed: int = 11, end: datetime | None = None) -> int:
        """Feed benign history so baselines (new-country rules, ML profiles) are populated."""
        from aegis.simulator import build_dataset

        end = end or datetime.now(UTC)
        envs = build_dataset(days, seed, start=end - timedelta(days=days))
        return self.process(envs)
