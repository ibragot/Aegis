"""Stream processors - one class per microservice.

A processor is pure business logic: it receives a batch of bus messages and
returns the messages it wants to publish. It knows nothing about Kafka, which
is why the exact same classes run inside `aegis run <service>` (one Kafka
consumer per container) and inside the in-process `LocalPipeline`.

    raw.*  ──collector──▶ events.{auth,cloud,network}
                              ├──auth-analyzer────▶ alerts
                              ├──cloud-analyzer───▶ alerts
                              ├──network-analyzer─▶ alerts
                              ├──ml-inference─────▶ alerts
                              └──indexer──────────▶ (PostgreSQL events + entity graph, S3 archive)
    alerts ──correlator──▶ incidents ──investigator──▶ (reports in PostgreSQL)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

from aegis.bus.base import (
    ALERTS,
    DEAD_LETTER,
    EVENT_TOPICS,
    EVENTS_AUTH,
    EVENTS_CLOUD,
    EVENTS_NETWORK,
    INCIDENTS,
    RAW_TOPICS,
    Message,
    topic_for_category,
)
from aegis.collectors import normalize
from aegis.config import Settings, get_settings
from aegis.detection import Correlator
from aegis.entities import is_strong
from aegis.graph.builder import graph_elements
from aegis.observability import metrics
from aegis.rules import RulesEngine, load_rules
from aegis.schema import Alert, Event
from aegis.state import StateStore
from aegis.storage.archive import Archiver
from aegis.storage.db import Repository

log = logging.getLogger(__name__)
Out = tuple[str, str | None, dict]  # (topic, key, value)


@dataclass
class Processor:
    name: str
    topics: list[str]
    group: str = ""
    tick_interval: float = 0.0
    _last_tick: float = field(default=0.0, repr=False)

    def handle(self, messages: list[Message]) -> list[Out]:
        raise NotImplementedError

    def tick(self) -> list[Out]:
        return []

    def maybe_tick(self, force: bool = False) -> list[Out]:
        now = time.monotonic()
        if self.tick_interval and (force or now - self._last_tick >= self.tick_interval):
            self._last_tick = now
            return self.tick()
        return []


class CollectorProcessor(Processor):
    """Parse + normalize + enrich raw logs; route by category; archive raw records to S3."""

    def __init__(self, archiver: Archiver | None = None):
        super().__init__("collector", list(RAW_TOPICS.values()), "collector", tick_interval=10)
        self.archiver = archiver

    def handle(self, messages: list[Message]) -> list[Out]:
        out: list[Out] = []
        parsed = []
        for m in messages:
            try:
                parsed.append((normalize(m.value), m))
            except Exception as exc:  # poison message -> dead-letter queue, keep going
                metrics.PROCESSING_ERRORS.labels(self.name).inc()
                out.append((DEAD_LETTER, None, {"error": str(exc), "message": m.value, "topic": m.topic}))
        # A batch mixes several raw topics; emit in event-time order so that stateful
        # analyzers downstream see a sensible ordering (see README: event time vs processing time).
        parsed.sort(key=lambda pm: pm[0].timestamp)
        for evt, m in parsed:
            if self.archiver:
                self.archiver.add(m.value)
            out.append((topic_for_category(evt.category), evt.entity_key, evt.model_dump(mode="json")))
        return out

    def tick(self) -> list[Out]:
        if self.archiver:
            self.archiver.flush()
        return []


def _alert_out(alert: Alert) -> Out:
    key = next((e.id for e in alert.entities if is_strong(e)), alert.rule_id)
    metrics.ALERTS.labels(alert.detector, alert.rule_id, alert.severity.value).inc()
    return (ALERTS, key, alert.model_dump(mode="json"))


class AnalyzerProcessor(Processor):
    """Runs the YAML rules for one analyzer kind (auth | cloud | network)."""

    TOPIC = {"auth": EVENTS_AUTH, "cloud": EVENTS_CLOUD, "network": EVENTS_NETWORK}

    def __init__(self, kind: str, settings: Settings | None = None, state: StateStore | None = None):
        super().__init__(f"{kind}-analyzer", [self.TOPIC[kind]], f"{kind}-analyzer")
        settings = settings or get_settings()
        self.engine = RulesEngine(load_rules(settings.rules_dir, analyzer=kind), state)
        log.info("%s loaded %d rules", self.name, len(self.engine.rules))

    def handle(self, messages: list[Message]) -> list[Out]:
        out = []
        events = sorted((Event(**m.value) for m in messages), key=lambda e: e.timestamp)
        for evt in events:
            for alert in self.engine.process(evt):
                out.append(_alert_out(alert))
        return out


class MLProcessor(Processor):
    def __init__(self, engine=None, state: StateStore | None = None):
        super().__init__("ml-inference", list(EVENT_TOPICS), "ml-inference")
        if engine is None:
            from aegis.ml.inference import MLEngine

            engine = MLEngine(state=state)
        self.engine = engine

    def handle(self, messages: list[Message]) -> list[Out]:
        events = [Event(**m.value) for m in messages]
        events.sort(key=lambda e: e.timestamp)
        return [_alert_out(a) for a in self.engine.process_batch(events)]


class IndexerProcessor(Processor):
    """Writes events to PostgreSQL and maintains the entity graph (nodes + edges)."""

    def __init__(self, repo: Repository):
        super().__init__("indexer", list(EVENT_TOPICS), "indexer")
        self.repo = repo

    def handle(self, messages: list[Message]) -> list[Out]:
        events = [Event(**m.value) for m in messages]
        self.repo.save_events(events)
        nodes, edges = [], []
        for e in events:
            n, ed = graph_elements(e)
            nodes += n
            edges += ed
        # chunk to keep statements a reasonable size
        for i in range(0, max(len(nodes), len(edges)), 500):
            self.repo.upsert_graph(nodes[i : i + 500], edges[i : i + 500])
        return []


class CorrelatorProcessor(Processor):
    def __init__(self, repo: Repository, settings: Settings | None = None):
        super().__init__("correlator", [ALERTS], "correlator", tick_interval=15)
        settings = settings or get_settings()
        self.correlator = Correlator(repo, settings.correlation_window_minutes)

    def handle(self, messages: list[Message]) -> list[Out]:
        out = []
        alerts = sorted((Alert(**m.value) for m in messages), key=lambda a: a.event_time)
        for alert in alerts:
            inc = self.correlator.process(alert)
            out.append((INCIDENTS, str(inc.incident_id), {"incident_id": inc.incident_id,
                                                          "risk_level": inc.risk_level,
                                                          "alert_count": len(inc.alert_ids)}))
        return out

    def tick(self) -> list[Out]:
        return [(INCIDENTS, str(i.incident_id), {"incident_id": i.incident_id, "risk_level": i.risk_level,
                                                 "alert_count": len(i.alert_ids)})
                for i in self.correlator.reconcile()]


class InvestigatorProcessor(Processor):
    """Debounced: waits until an incident has been quiet for `debounce_s` before (re)investigating."""

    def __init__(self, investigator, debounce_s: float = 20.0, use_llm: bool = True):
        super().__init__("investigator", [INCIDENTS], "investigator", tick_interval=2)
        self.investigator = investigator
        self.debounce_s = debounce_s
        self.use_llm = use_llm
        self.pending: dict[int, float] = {}

    def handle(self, messages: list[Message]) -> list[Out]:
        now = time.monotonic()
        for m in messages:
            self.pending[int(m.value["incident_id"])] = now
        return self.tick() if self.debounce_s == 0 else []

    def tick(self) -> list[Out]:
        now = time.monotonic()
        ready = [i for i, t in self.pending.items() if now - t >= self.debounce_s]
        for incident_id in ready:
            self.pending.pop(incident_id, None)
            inc = self.investigator.repo.get_incident(incident_id)
            if inc and self.investigator.should_investigate(inc):
                try:
                    self.investigator.investigate(inc, use_llm=self.use_llm)
                except Exception:
                    log.exception("investigation of %s failed", incident_id)
                    metrics.PROCESSING_ERRORS.labels(self.name).inc()
        return []
