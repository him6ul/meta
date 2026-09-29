"""Prometheus metrics for outbound Meta calls, inbound webhooks and the app's own HTTP surface."""
import re

from prometheus_client import Counter, Gauge, Histogram

LATENCY_BUCKETS = (0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 20)

# --- Outbound: Meta Graph API ---
META_REQUESTS = Counter(
    "meta_api_requests_total",
    "Calls made to the Meta Graph API (final outcome, after retries)",
    ["endpoint", "method", "status", "outcome"],
)
META_ATTEMPTS = Counter(
    "meta_api_attempts_total",
    "Individual HTTP attempts to the Meta Graph API (includes retries)",
    ["endpoint", "method", "status"],
)
META_LATENCY = Histogram(
    "meta_api_request_duration_seconds",
    "Latency of a single HTTP attempt to the Meta Graph API",
    ["endpoint", "method"],
    buckets=LATENCY_BUCKETS,
)
META_ERRORS = Counter(
    "meta_api_errors_total",
    "Meta error responses by Graph error code/type",
    ["endpoint", "code", "subcode", "type"],
)
META_RETRIES = Counter(
    "meta_api_retries_total",
    "Retries performed against the Meta Graph API",
    ["endpoint", "reason"],
)
META_RATE_LIMIT = Gauge(
    "meta_api_rate_limit_usage_percent",
    "Latest usage percentage reported by Meta rate-limit headers",
    ["header", "scope_id", "usage_type", "metric"],
)
META_REGAIN_ACCESS = Gauge(
    "meta_api_rate_limit_regain_access_minutes",
    "estimated_time_to_regain_access from X-Business-Use-Case-Usage",
    ["scope_id", "usage_type"],
)
META_CIRCUIT_STATE = Gauge(
    "meta_api_circuit_state",
    "Circuit breaker state: 0=closed, 1=half-open, 2=open",
)
META_CIRCUIT_REJECTIONS = Counter(
    "meta_api_circuit_rejections_total",
    "Calls rejected locally because the circuit breaker was open",
)

# --- Inbound: webhooks ---
WEBHOOK_EVENTS = Counter(
    "meta_webhook_events_total",
    "Webhook deliveries received from Meta",
    ["object", "field", "signature"],
)
WEBHOOK_VERIFICATIONS = Counter(
    "meta_webhook_verifications_total",
    "Webhook subscription verification handshakes",
    ["result"],
)

# --- The app's own HTTP surface ---
HTTP_REQUESTS = Counter(
    "app_http_requests_total", "Inbound HTTP requests", ["route", "method", "status"]
)
HTTP_LATENCY = Histogram(
    "app_http_request_duration_seconds",
    "Inbound HTTP request latency",
    ["route", "method"],
    buckets=LATENCY_BUCKETS,
)

_ID_SEGMENT = re.compile(r"^(\d+|act_\d+|\d+_\d+)$")


def normalize_endpoint(path: str) -> str:
    """Collapse object IDs so metric label cardinality stays bounded: '/1234/messages' -> '/{id}/messages'."""
    parts = [p for p in path.strip("/").split("/") if p]
    if parts and re.fullmatch(r"v\d+\.\d+", parts[0]):
        parts = parts[1:]
    return "/" + "/".join("{id}" if _ID_SEGMENT.match(p) else p for p in parts)
