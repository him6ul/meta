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
                        └─(read-only)─► audit-shipper ──► S3 Object Lock (WORM, LocalStack locally)
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
| LocalStack S3 (Object Lock archive) | http://localhost:4566 (`make audit-archive-ls`) |
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

Records are also archived off-host to S3 Object Lock, below.

## Audit archive: S3 Object Lock (`app/audit_shipper.py`)

A separate **audit-shipper** container tails the audit log (mounted **read-only**) and uploads it as
immutable segments. It holds the only S3 credentials, and they are write-only: it can add segments but
can't list, delete or change retention. Compromising the app therefore doesn't expose the archive.

```
s3://<bucket>/audit/meta-api-tester/2026/09/29/000000000001-000000000036.jsonl
  ObjectLockMode=COMPLIANCE  RetainUntilDate=+N days  SSE-KMS  x-amz-checksum-sha256
  metadata: first-seq, last-seq, first-prev-hash, last-hash, sha256, source-host
```

- Segments flush every `AUDIT_SHIP_FLUSH_SECONDS` (10s) or 500 records. The checkpoint (byte offset + last
  seq/hash) advances only after S3 confirms the write, so restarts resume with no loss and no duplicates.
- **Nothing forged is archived.** Every record must chain onto the last archived hash. A break halts
  shipping.
- **Rewrites are detected.** Every 60s, and at startup, the shipper checks that the local file still
  contains the exact record it last archived. If someone truncates the file or rewrites history with a
  fresh, internally valid chain (which *passes* the local `/api/audit/verify`), shipping halts with
  `source_diverged` and 🚨 `AuditArchiveDiverged` goes to Slack. The shipper stays halted until a human
  investigates. `make audit-verify-s3` then lists every local seq that differs from the archive.
- The shipper audits its own actions (`audit.segment.shipped` with key/version/hash, `ship_failed`,
  `shipping.halted`) as JSON lines on stdout.

**Verifier** (`make audit-verify-s3`, or `python -m app.audit_shipper verify [--compare-local FILE]`)
reads **every object version**, checks each segment's SHA-256, confirms each has an unexpired lock, rebuilds
the chain from seq 1, and reports gaps, conflicting duplicates and local mismatches. It also reads
through **delete markers**: a plain DELETE on a locked bucket is allowed but only hides the version. The
locked record is still verified and the marker is reported as a delete attempt. Exit code 1 if anything is
off.

Alerts: `AuditArchiveDiverged` (critical), `AuditShipperDown` (critical), `AuditArchiveLagging` (>5 min
unarchived), `AuditArchiveUploadFailures`. The Grafana dashboard shows written vs archived seq, lag, time
since last upload, and chain integrity.

**Local:** LocalStack enforces Object Lock (COMPLIANCE, 1 day), so version deletes and retention changes
are refused. Its archive is **ephemeral**, lost when the container is recreated. Use
`make audit-archive-reset-local` to wipe it together with the shipper checkpoint.

### Production bucket (`infra/audit-bucket`, Terraform)

```bash
cd infra/audit-bucket
cp terraform.tfvars.example terraform.tfvars   # bucket name, shipper role, admins
terraform init && terraform plan
```

It creates:
- the bucket with Object Lock, versioning and default retention
- a dedicated KMS key with rotation, and a public access block
- a bucket policy that denies non-TLS access, denies writes under any other KMS key, denies
  `s3:BypassGovernanceRetention` (except optional break-glass principals), and denies
  lock/versioning/lifecycle/policy changes (except `admin_principal_arns`)
- a Glacier IR transition after 90 days
- least-privilege **shipper** (write-only) and **verifier** (read-only) IAM policies
- a **CloudTrail data-event trail** on the bucket, so every read, write and delete attempt against the
  archive is itself recorded

Then set the `shipper_env` output values in `.env` (with `AUDIT_S3_ENDPOINT_URL=` empty) and give the
shipper the IAM role.

> ⚠️ `lock_mode` defaults to **GOVERNANCE** so you can validate first. **COMPLIANCE** can't be shortened
> or removed by anyone, including the AWS root account, until retention expires. You'll pay to store every
> object for the full period. Switch deliberately.

Remaining trust boundary: records written locally but not yet shipped (≤10s by default) exist only on the
host. For zero-window capture, have the app write synchronously to S3 or a stream (e.g. Kinesis/Firehose).
and periodically anchor the `head_hash` externally, since a local file can be replaced wholesale.

## Local dev

```bash
make install && make test     # 29 tests, pytest + respx
make mock &                   # mock on :8081
META_GRAPH_BASE_URL=http://localhost:8081 META_ACCESS_TOKEN=x make run
```
