"""Structured JSON logging (with trace correlation + secret redaction) and OpenTelemetry tracing."""
import json
import logging
import re
import sys
from datetime import datetime, timezone

from opentelemetry import trace

from app.config import Settings

_SECRET_PATTERNS = [
    (re.compile(r"(access_token=)[^&\s\"']+"), r"\1***"),
    (re.compile(r"(appsecret_proof=)[^&\s\"']+"), r"\1***"),
    (re.compile(r"(input_token=)[^&\s\"']+"), r"\1***"),
    (re.compile(r"(Bearer\s+)[A-Za-z0-9._\-]+"), r"\1***"),
    (re.compile(r"\bEA[A-Za-z0-9]{20,}\b"), "EA***"),  # Meta user/page/system tokens
]


def redact(text: str) -> str:
    for pattern, repl in _SECRET_PATTERNS:
        text = pattern.sub(repl, text)
    return text


class JsonFormatter(logging.Formatter):
    _RESERVED = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {"message"}

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        span_ctx = trace.get_current_span().get_span_context()
        if span_ctx.is_valid:
            payload["trace_id"] = format(span_ctx.trace_id, "032x")
            payload["span_id"] = format(span_ctx.span_id, "016x")
        for key, value in record.__dict__.items():
            if key not in self._RESERVED and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return redact(json.dumps(payload, default=str))


def setup_logging(settings: Settings) -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(settings.log_level.upper())
    for noisy in ("uvicorn.access", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def setup_tracing(settings: Settings, app) -> None:
    """Export spans via OTLP/HTTP when OTEL_EXPORTER_OTLP_ENDPOINT is set; otherwise tracing is a no-op."""
    if not settings.otel_exporter_otlp_endpoint:
        return
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    provider = TracerProvider(resource=Resource.create({"service.name": settings.otel_service_name}))
    endpoint = settings.otel_exporter_otlp_endpoint.rstrip("/") + "/v1/traces"
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
    trace.set_tracer_provider(provider)
    FastAPIInstrumentor.instrument_app(app, excluded_urls="metrics,health",
                                       exclude_spans=["send", "receive"])
    HTTPXClientInstrumentor().instrument()
