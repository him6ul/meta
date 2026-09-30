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
META_LOCAL_RATE_LIMITED = Counter("meta_api_local_rate_limited_total",
                                  "Calls refused locally (never sent) to stay under Meta limits", ["reason"])
META_RATE_LIMIT_WAIT = Histogram("meta_api_rate_limit_wait_seconds", "Delay added by proactive pacing",
                                 ["reason"], buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5))
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

WEBHOOK_DUPLICATES = Counter("meta_webhook_events_deduplicated_total",
                             "Webhook events dropped as redeliveries of already-processed events",
                             ["object", "kind"])
WEBHOOK_REJECTED = Counter("meta_webhook_rejected_total", "Webhook deliveries rejected", ["reason"])

# --- WhatsApp delivery (status webhooks correlated with sends) ---
WA_MESSAGES_SENT = Counter("whatsapp_messages_sent_total", "WhatsApp messages accepted by the Cloud API", ["kind"])
WA_STATUS_EVENTS = Counter("whatsapp_status_events_total", "First-time status webhooks by status", ["status"])
WA_DELIVERY_LATENCY = Histogram("whatsapp_status_latency_seconds",
                                "Time from API accept to each status (sent / delivered / read)", ["status"],
                                buckets=(0.5, 1, 2, 5, 10, 30, 60, 300, 900, 3600, 21600, 86400))
WA_FAILURES = Counter("whatsapp_message_failures_total", "Failed deliveries by Meta error", ["code", "title"])
WA_MESSAGES_STALE = Gauge("whatsapp_messages_stale_undelivered",
                          "Messages accepted/sent but not delivered within the stale threshold")

# --- Access token health (from /debug_token) ---
META_TOKEN_VALID = Gauge("meta_token_valid", "1 if Meta reports the access token as valid")
META_TOKEN_EXPIRES = Gauge("meta_token_expires_timestamp_seconds", "Token expiry (unix time, 0 = never)")
META_TOKEN_DATA_ACCESS_EXPIRES = Gauge("meta_token_data_access_expires_timestamp_seconds",
                                       "Data-access expiry (unix time, 0 = never)")
META_TOKEN_MISSING_SCOPES = Gauge("meta_token_missing_required_scopes", "Required scopes the token lacks")
META_TOKEN_CHECK_LAST_SUCCESS = Gauge("meta_token_check_last_success_timestamp_seconds",
                                      "Last successful /debug_token check")
META_TOKEN_CHECK_FAILURES = Counter("meta_token_check_failures_total", "Failed /debug_token checks")

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
for _reason in ("signature_missing_secret", "signature_invalid", "invalid_json"):
    WEBHOOK_REJECTED.labels(_reason)
for _status in ("sent", "delivered", "read", "failed"):
    WA_STATUS_EVENTS.labels(_status)
for _kind in ("text", "template"):
    WA_MESSAGES_SENT.labels(_kind)
for _reason in ("regain_access", "usage_hard", "wa_throughput", "wa_pair"):
    META_LOCAL_RATE_LIMITED.labels(_reason)

# Unknown until the first successful /debug_token check (NaN never matches `== 0`), so a fresh process
# (or another service that imports this module) can't raise a false "token invalid" alert.
META_TOKEN_VALID.set(float("nan"))
