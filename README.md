# Meta API Tester

A FastAPI test harness for the **Meta Graph API** (WhatsApp Cloud API, Facebook Pages, Instagram, and any
Graph object) with production-style resilience and full observability. It ships with a **mock Meta server**
with fault injection, so the whole stack works before you have credentials.

```
 loadgen ──► app (FastAPI :8000) ──► Meta Graph API  (graph.facebook.com  or  mock-meta :8081)
               │  ▲                        │
               │  └── webhooks ◄───────────┘  (X-Hub-Signature-256 verified)
               ├─► /metrics ──► Prometheus :9090 ──► Grafana :3000 (dashboard)
               │                    └─► Alertmanager :9093 ──► Slack
               │                                  └────────► app /webhooks/alertmanager (audited)
               ├─► OTLP traces ──► Jaeger :16686
               ├─► JSON logs (stdout, trace_id-correlated, tokens redacted)
               └─► audit trail (append-only, hash-chained JSONL, /api/audit)
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
| Alertmanager (silences) | http://localhost:9093 |
| Fake Slack inbox (when no real webhook set) | http://localhost:8081/_mock/slack |
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
- `SLACK_WEBHOOK_URL` – a Slack [incoming webhook](https://api.slack.com/messaging/webhooks); the channel is
  chosen when you create the webhook
- `APP_API_KEYS=alice:<key>,ci-bot:<key>` – require `X-API-Key` on `/api/*` and attribute actions to a name

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
| GET | `/api/audit?action=&actor=&request_id=&outcome=&limit=` | query the audit trail (newest first) |
| GET | `/api/audit/verify` | recompute the hash chain |
| POST | `/webhooks/alertmanager` | Alertmanager notification receiver (audited) |
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
circuit open, p95 latency >2s, OAuth error 190 (token expired/revoked), invalid webhook signatures,
scrape target down, audit writes failing, and bursts of unauthenticated API access.

## Alerting (Alertmanager → Slack)

`monitoring/alertmanager/alertmanager.yml` routes `critical` alerts to a faster-repeating receiver
(30m vs 4h) with a :rotating_light: prefix. Both receivers send resolved notices too. Messages
(`templates/slack.tmpl`) are colour-coded and include the summary, labels, start/resolve times and
**Grafana** / **Silence** buttons. Inhibition rules suppress error-rate/latency/throttle alerts while the
circuit is open, and suppress everything while the app is down.

The webhook URL is read from `$SLACK_WEBHOOK_URL` at container start and written to a file that
Alertmanager reads (`api_url_file`), so the secret never lands in git. Without it, alerts go to the mock's
fake Slack inbox, so you can test the full path locally (`make chaos-outage`, wait ~1 min, `make slack`).

## Audit trail (`app/audit.py`)

Every action writes one record to an append-only JSONL file (`AUDIT_LOG_PATH`, Docker volume `audit-data`)
and to the `audit` logger:

| Action | When | Actor |
|---|---|---|
| `http.request` | every inbound request (incl. denied), except `/health` `/ready` `/metrics` | API-key name, else `unverified:<X-Actor>` / `anonymous` |
| `meta.api.get/post/delete` | every outbound Meta call: status, attempts, duration, Meta error + `fbtrace_id`, created object IDs (`wamid…`, post id) | inherited from the request |
| `meta.circuit.state_changed` | breaker opens / half-opens / closes | `system` |
| `webhook.meta.verify`, `webhook.meta.received` | handshakes and deliveries, including rejected signatures | `meta` / `unknown` |
| `alert.notification` | every notification Alertmanager sends | `alertmanager` |
| `app.started`, `app.stopped` | lifecycle | `system` |
| `mock.config.changed`, `mock.webhook.sent` | chaos changes (before/after) – mock's stdout | `X-Actor` |

Records carry `request_id` (echoed as `X-Request-ID`) and `trace_id`, so one API call can be followed
across the audit trail, logs and Jaeger. Tokens are masked, and request/message payloads are stored only as
a SHA-256 digest + size: no PII or secrets in the trail, but a payload can still be proven against it.

**Tamper evidence:** each record's `hash = sha256(prev_hash + record)`. `GET /api/audit/verify`
recomputes the chain and reports the first altered, deleted or reordered record. **Availability:** a
failed write increments `audit_write_failures_total` (critical alert) and makes `/ready` return 503. That
takes the instance out of rotation instead of letting it act without a record.

**Identity:** without `APP_API_KEYS`, actors are self-declared (`X-Actor`) and labelled `unverified:`.
Set API keys (or put an authenticating proxy in front) when the actor must be trustworthy.

For production, ship the file or the `audit` log stream to WORM/immutable storage (e.g. S3 Object Lock)
and periodically anchor the `head_hash` externally, since a local file can be replaced wholesale.

## Local dev

```bash
make install && make test     # 21 tests, pytest + respx
make mock &                   # mock on :8081
META_GRAPH_BASE_URL=http://localhost:8081 META_ACCESS_TOKEN=x make run
```
