"""Online ML inference - what the `ml-inference` Kafka consumer runs.

Batches of events are featurized one by one (the extractor is stateful and
order-matters), then scored by every model in a single vectorized call -
batching turns Isolation Forest from ~8 ms/event into ~0.02 ms/event.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

import joblib
import numpy as np

from aegis.config import get_settings
from aegis.entities import entities_from_event
from aegis.ml.features import explain
from aegis.ml.pipeline import ARTIFACT_NAME, ensemble_score, train_and_evaluate
from aegis.observability import metrics
from aegis.schema import Alert, Event, Severity
from aegis.state import MemoryStateStore, StateStore

log = logging.getLogger(__name__)


def load_or_train(model_dir: Path | None = None) -> dict:
    model_dir = model_dir or get_settings().model_dir
    path = model_dir / ARTIFACT_NAME
    if not path.exists():
        log.warning("no trained model at %s - training a small one now (run `aegis train` for the full model)", path)
        train_and_evaluate(model_dir=model_dir, report_dir=model_dir / "reports", train_days=5, val_days=2,
                           test_days=1)
    return joblib.load(path)


class MLEngine:
    def __init__(self, artifact: dict | None = None, model: str | None = None, state: StateStore | None = None,
                 suppression_seconds: float = 600):
        self.artifact = artifact or load_or_train()
        self.model = model or get_settings().ml_model
        self.fx = self.artifact["extractor"]
        self.models = self.artifact["models"]
        self.mean, self.std = self.artifact["baseline_mean"], self.artifact["baseline_std"]
        self.state = state or MemoryStateStore()
        self.suppression = suppression_seconds
        self.models["markov_sequence"].reset_state()

    def score(self, events: list[Event]) -> tuple[np.ndarray, dict[str, np.ndarray], np.ndarray]:
        t = time.perf_counter()
        X = np.vstack([self.fx.transform(e) for e in events])
        norm = {}
        for name, m in self.models.items():
            raw = m.score_events(events) if name == "markov_sequence" else m.score(X)
            norm[name] = raw / m.threshold
        norm["ensemble"] = ensemble_score(norm)
        per_event = (time.perf_counter() - t) / len(events)
        metrics.ML_INFERENCE_SECONDS.labels(self.model).observe(per_event)
        return norm[self.model], norm, X

    def process_batch(self, events: list[Event]) -> list[Alert]:
        if not events:
            return []
        final, norm, X = self.score(events)
        alerts = []
        for i, evt in enumerate(events):
            s = float(final[i])
            metrics.ML_SCORE.labels(self.model).observe(s)
            if s < 1.0:
                continue
            # Suppression: at most one ML alert per identity per 10 minutes, otherwise a
            # single anomalous burst produces dozens of near-identical alerts.
            if not self.state.cooldown(f"ml:{evt.entity_key}", evt.timestamp.timestamp(), self.suppression):
                continue
            severity = Severity.high if s >= 4 else Severity.medium if s >= 2 else Severity.low
            reasons = explain(X[i], self.mean, self.std)
            alerts.append(
                Alert(
                    event_time=evt.timestamp,
                    detector="ml",
                    rule_id="AEG-ML-001",
                    rule_name="Behavioral anomaly for identity",
                    severity=severity,
                    score=round(min(s / 4, 1.0), 3),
                    description=(
                        f"{evt.action} by {evt.entity_key} deviates from its learned baseline "
                        f"(score {s:.2f}x threshold, model={self.model})."
                    ),
                    # for network flows the "target" is just the destination IP - keep it an ip entity
                    entities=entities_from_event(
                        evt, ["principal", "src_ip", "dst_ip" if evt.category == "network" else "target_resource"]),
                    event_ids=[evt.event_id],
                    evidence={
                        "action": evt.action,
                        "outcome": evt.outcome,
                        "category": evt.category,
                        "model": self.model,
                        "normalized_score": round(s, 3),
                        "model_scores": {k: round(float(v[i]), 3) for k, v in norm.items()},
                        "top_features": reasons,
                    },
                )
            )
        return alerts
