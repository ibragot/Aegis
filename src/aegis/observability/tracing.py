"""OpenTelemetry tracing.

When `OTEL_EXPORTER_OTLP_ENDPOINT` is set, spans are exported over OTLP/gRPC to
the OpenTelemetry Collector (deploy/otel/otel-collector.yaml), which forwards
them to Jaeger. When it is not set, tracing is a no-op.

Distributed tracing across Kafka works by *propagating context in message
headers*: the producer injects a W3C `traceparent` header, and the consumer
extracts it and starts its span as a child. That is how one trace can show an
event's whole journey through five different services.
"""

from __future__ import annotations

import contextlib
import logging
from collections.abc import Iterator

from opentelemetry import context, propagate, trace

log = logging.getLogger(__name__)
_configured = False


def setup_tracing(service_name: str, endpoint: str | None) -> None:
    global _configured
    if _configured or not endpoint:
        return
    try:
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        log.warning("OTLP exporter not installed; tracing disabled")
        return
    provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint, insecure=True)))
    trace.set_tracer_provider(provider)
    _configured = True
    log.info("tracing enabled -> %s", endpoint)


def tracer():
    return trace.get_tracer("aegis")


def inject_headers() -> dict[str, str]:
    carrier: dict[str, str] = {}
    propagate.inject(carrier)
    return carrier


@contextlib.contextmanager
def span_from_headers(name: str, headers: dict[str, str] | None, **attributes) -> Iterator[trace.Span]:
    ctx = propagate.extract(headers or {})
    token = context.attach(ctx)
    try:
        with tracer().start_as_current_span(name, kind=trace.SpanKind.CONSUMER) as span:
            for k, v in attributes.items():
                span.set_attribute(k, v)
            yield span
    finally:
        context.detach(token)
