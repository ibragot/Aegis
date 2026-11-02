"""Prometheus metrics shared by all services.

Prometheus *pulls* (scrapes) metrics: every service exposes `/metrics` over HTTP
and Prometheus fetches it every 15s (see deploy/prometheus/prometheus.yml).
Grafana then queries Prometheus with PromQL, e.g.

    sum(rate(aegis_events_processed_total[1m])) by (service)          # throughput
    histogram_quantile(0.99, rate(aegis_ml_inference_seconds_bucket[5m]))  # p99 latency
"""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram, start_http_server

EVENTS_PROCESSED = Counter("aegis_events_processed_total", "Messages processed", ["service", "topic"])
PROCESSING_ERRORS = Counter("aegis_processing_errors_total", "Messages that failed processing", ["service"])
PROCESSING_SECONDS = Histogram(
    "aegis_processing_seconds", "Time to process one batch", ["service"],
    buckets=(0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)
ALERTS = Counter("aegis_alerts_total", "Alerts raised", ["detector", "rule_id", "severity"])
ML_INFERENCE_SECONDS = Histogram(
    "aegis_ml_inference_seconds", "Per-event feature extraction + model scoring latency", ["model"],
    buckets=(0.0001, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1),
)
ML_SCORE = Histogram("aegis_ml_anomaly_score", "Normalized anomaly score (1.0 = threshold)", ["model"],
                     buckets=(0.1, 0.25, 0.5, 0.75, 1.0, 1.5, 2, 3, 5))
INCIDENTS = Counter("aegis_incidents_total", "Incidents created", ["risk_level"])
INCIDENT_UPDATES = Counter("aegis_incident_updates_total", "Alerts merged into existing incidents")
OPEN_INCIDENTS = Gauge("aegis_open_incidents", "Open incidents by level", ["risk_level"])
INVESTIGATIONS = Counter("aegis_investigations_total", "Investigation reports generated", ["generator"])
LLM_SECONDS = Histogram("aegis_llm_seconds", "LLM call latency", buckets=(1, 2, 5, 10, 20, 40, 80, 160))
CONSUMER_LAG = Gauge("aegis_consumer_lag", "Kafka consumer lag (messages)", ["group", "topic", "partition"])
RAW_ARCHIVED = Counter("aegis_raw_archived_total", "Raw records archived to the data lake")


def serve(port: int) -> None:
    start_http_server(port)
