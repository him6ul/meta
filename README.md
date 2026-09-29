# Meta API Tester

A FastAPI test harness for the **Meta Graph API** (WhatsApp Cloud API, Facebook Pages, Instagram, and any
Graph object) with production-style resilience and full observability. It ships with a **mock Meta server**
with fault injection, so the whole stack works before you have credentials.

```
 loadgen ──► app (FastAPI :8000) ──► Meta Graph API  (graph.facebook.com  or  mock-meta :8081)
               │  ▲                        │
               │  └── webhooks ◄───────────┘  (X-Hub-Signature-256 verified)
               ├─► /metrics ──► Prometheus :9090 (alerts) ──► Grafana :3000 (dashboard)
               ├─► OTLP traces ──► Jaeger :16686
               └─► JSON logs (stdout, trace_id-correlated, tokens redacted)
```

## Quick start (mock Meta, no credentials needed)

```bash
docker compose up -d --build
```

| What | URL |
|---|---|
| Swagger test console | http://localhost:8000/docs |
| Grafana dashboard ("Meta API" folder) | http://localhost:3000 |
| Prometheus + alerts | http://localhost:9090/alerts |
| Jaeger traces (service `meta-api-tester`) | http://localhost:16686 |
| Mock Meta control | http://localhost:8081/docs |

Generate traffic and break things:

```bash
make load            # 5 rps background load generator
make chaos-errors    # 30% Meta 500s  -> retries climb, success stays high
make chaos-throttle  # 40% code 4 / 130429 -> throttled outcome, MetaApiThrottled alert
make chaos-outage    # all 503 -> circuit breaker opens, /ready = 503, MetaApiCircuitOpen alert
make chaos-reset
make webhook         # mock sends a signed WhatsApp webhook to the app
```

## Using the real Meta API

```bash
cp .env.example .env    # fill in the values below
docker compose up -d --build
```

- `META_GRAPH_BASE_URL=https://graph.facebook.com` (compose defaults to the mock otherwise)
- `META_ACCESS_TOKEN` – a System User token is best for server-to-server calls
- `META_APP_ID`, `META_APP_SECRET` – enables `appsecret_proof` on every call, `/api/debug-token`, and webhook signature checks
- `WHATSAPP_PHONE_NUMBER_ID`, `META_PAGE_ID`, `INSTAGRAM_ACCOUNT_ID` – as needed

For webhooks, expose `/webhooks/meta` publicly (e.g. `ngrok http 8000`), then set the callback URL and
`META_WEBHOOK_VERIFY_TOKEN` in the App Dashboard.

## Endpoints

| Method | Path | Meta call |
|---|---|---|
| GET | `/api/me` | `GET /me` |
| GET | `/api/debug-token` | `GET /debug_token` (validity, scopes, expiry) |
| GET | `/api/graph/{path}?fields=…` | generic GET passthrough |
| POST | `/api/whatsapp/messages` | `POST /{phone-id}/messages` (text) |
| POST | `/api/whatsapp/templates` | `POST /{phone-id}/messages` (template) |
| GET/POST | `/api/pages/posts` | `GET /{page-id}/posts`, `POST /{page-id}/feed` |
| GET | `/api/instagram/media` | `GET /{ig-id}/media` |
| GET | `/api/rate-limits` | last usage headers + circuit state |
| GET/POST | `/webhooks/meta` | verification handshake / event delivery |
| GET | `/webhooks/meta/recent` | last 50 received webhook payloads |
| GET | `/health`, `/ready`, `/metrics` | ops |

Meta errors come back with Meta's own error body. Throttling maps to **429**, Meta 5xx to **502**,
an open circuit to **503** and an unreachable upstream to **504**.

## Resilience (`app/graph_client.py`)

- **Retries** with exponential backoff + jitter on transport errors, HTTP 429/5xx, `is_transient`, and Graph
  throttle codes (`4, 17, 32, 341, 613, 800xx, 130429, 131056`). Throttle backoff is doubled.
- **Circuit breaker**: opens after N consecutive server/throttle failures, half-opens after a cooldown.
  Client errors (bad params, code 190 token errors) do *not* trip it.
- **Rate-limit tracking**: parses `X-App-Usage`, `X-Business-Use-Case-Usage` (including
  `estimated_time_to_regain_access`) and `X-Ad-Account-Usage` into gauges.
- **appsecret_proof** added automatically when `META_APP_SECRET` is set.

## Metrics & alerts

| Metric | Labels |
|---|---|
| `meta_api_requests_total` | endpoint, method, status, outcome (`success/failure/throttled/circuit_open`) |
| `meta_api_attempts_total` | endpoint, method, status (every attempt, incl. retries) |
| `meta_api_request_duration_seconds` | endpoint, method |
| `meta_api_errors_total` | endpoint, code, subcode, type |
| `meta_api_retries_total` | endpoint, reason |
| `meta_api_rate_limit_usage_percent` | header, scope_id, usage_type, metric |
| `meta_api_rate_limit_regain_access_minutes` | scope_id, usage_type |
| `meta_api_circuit_state` | 0 closed / 1 half-open / 2 open |
| `meta_webhook_events_total` | object, field, signature (`valid/invalid/unchecked`) |
| `app_http_requests_total`, `app_http_request_duration_seconds` | route, method, status |

Object IDs in paths are collapsed to `{id}` to keep label cardinality bounded.

Alerts (`monitoring/alerts.yml`): high error rate (>5%), rate-limit usage >75%, sustained throttling,
circuit open, p95 latency >2s, OAuth error 190 (token expired/revoked), invalid webhook signatures, and
scrape target down. To route them to Slack or PagerDuty, add Alertmanager.

## Local dev

```bash
make install && make test     # 12 tests, pytest + respx
make mock &                   # mock on :8081
META_GRAPH_BASE_URL=http://localhost:8081 META_ACCESS_TOKEN=x make run
```
