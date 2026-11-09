"""Distributed tracing (PR 10): a span for every request, every SQL statement and every call to card-service, sent over
OTLP/HTTP to the collector. Off unless OTEL_EXPORTER_OTLP_ENDPOINT is set, so tests and the sandbox pay nothing.

Our X-Trace-Id (Step 18) is put on each request span as `synapsepay.trace_id`, so a trace id quoted by a merchant is
searchable in Tempo; outbound calls carry W3C `traceparent`, which card-service will join when it gets spans of its own.
SQL spans record the statement with its placeholders, never the parameter values.
"""
import os


def enable_tracing(app, service_name: str = "synapsepay-api") -> bool:
    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not endpoint:
        return False
    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
    from opentelemetry.instrumentation.psycopg import PsycopgInstrumentor
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    provider = TracerProvider(resource=Resource.create({"service.name": service_name}))
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{endpoint.rstrip('/')}/v1/traces")))
    trace.set_tracer_provider(provider)

    def tag(span, scope):  # the trace id merchants quote, on the request's own span
        for name, value in scope.get("headers", []):
            if name == b"x-trace-id":
                span.set_attribute("synapsepay.trace_id", value.decode("latin-1")[:64])

    FastAPIInstrumentor.instrument_app(app, server_request_hook=tag, excluded_urls="health/live,health/region")
    PsycopgInstrumentor().instrument(enable_commenter=False)
    HTTPXClientInstrumentor().instrument()
    return True
