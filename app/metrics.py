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

# --- Audit trail ---
AUDIT_EVENTS = Counter("audit_events_total", "Audit records written", ["action", "outcome"])
AUDIT_WRITE_FAILURES = Counter("audit_write_failures_total", "Audit records that could not be persisted")
AUDIT_JOURNAL_LATENCY = Histogram("audit_journal_write_duration_seconds",
                                  "Synchronous off-host (S3 Object Lock) journal write latency",
                                  buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2))
AUDIT_JOURNAL_FAILURES = Counter("audit_journal_failures_total", "Failed journal write attempts", ["reason"])
AUDIT_REFUSED = Counter("audit_refused_actions_total",
                        "Actions refused because their audit record could not be made durable", ["kind"])
AUDIT_OUTCOME_UNRECORDED = Counter("audit_outcome_unrecorded_total",
                                   "Actions that happened but whose outcome record could not be made durable",
                                   ["kind"])

# --- Alert notifications ---
ALERT_NOTIFICATIONS = Counter("alert_notifications_total", "Alertmanager notifications received",
                              ["alertname", "status", "severity"])

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


# Pre-create labelled series at 0: Prometheus increase() ignores the first sample of a new series, so
# an alert on "any refusal" would otherwise miss the first burst.
for _kind in ("http_request", "meta_api", "webhook"):
    AUDIT_REFUSED.labels(_kind)
for _kind in ("http_request", "meta_api", "circuit"):
    AUDIT_OUTCOME_UNRECORDED.labels(_kind)
for _reason in ("unreachable", "503", "400", "401", "409"):
    AUDIT_JOURNAL_FAILURES.labels(_reason)
