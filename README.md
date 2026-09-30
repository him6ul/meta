# Meta API Tester

A FastAPI test harness for the **Meta Graph API** (WhatsApp Cloud API, Facebook Pages, Instagram, and any
Graph object) with production-style resilience and full observability. It ships with a **mock Meta server**
with fault injection, so the whole stack works before you have credentials.

```
 loadgen ──► lb (nginx :8000) ──► app replica 1..N (FastAPI) ──► Meta Graph API (graph.facebook.com | mock-meta)
                                   │  ▲                                 │
                                   │  └── webhooks (signed, deduped) ◄──┘
                                   │
                                   ├─ every action: unsequenced draft ─► audit-gateway :9102 ─► S3 Object Lock
                                   │    (write-ahead, fail-closed)        global sequencer      blocks/<n>.jsonl
                                   │                                      group commit, CAS     (If-None-Match)
                                   │                                      index + query API, scheduled verifier
                                   ├─► /metrics (per replica) ─► Prometheus ─► Grafana  ·  Alertmanager ─► Slack
                                   ├─► OTLP traces ─► Jaeger          └─► JSON logs ─► Alloy ─► Loki
                                   └─► replica cache of its own committed records (audit-<replica>.jsonl)
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
| Logs (Grafana → Explore → Loki) | http://localhost:3000/explore |
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
| GET | `/api/rate-limits` | last usage headers, circuit state, proactive pacing state |
| GET | `/api/token-status?refresh=` | token validity, expiry, missing scopes (from `/debug_token`) |
| GET | `/api/whatsapp/messages/{wamid}/status` | delivery state of one message |
| GET | `/api/whatsapp/delivery-stats?window_seconds=` | delivery/failure rate, top failure reasons, stuck count |
| GET/POST | `/webhooks/meta` | verification handshake / event delivery |
| GET | `/webhooks/meta/recent` | last 50 received webhook payloads |
| GET | `/api/audit?action=&actor=&request_id=&outcome=&limit=` | query the audit trail (newest first) |
| GET | `/api/audit/verify` | recompute the hash chain |
| POST | `/webhooks/alertmanager` | Alertmanager notification receiver (audited) |
| GET | `/health`, `/ready`, `/metrics` | ops |

Meta errors come back with Meta's own error body. Throttling maps to **429**, Meta 5xx to **502**,
an open circuit to **503** and an unreachable upstream to **504**. A call refused by local pacing gets
**429** with `Retry-After` and `"source": "local"`; it never reaches Meta.

## Production hardening

**Token health** (`app/token_monitor.py`) calls `/debug_token` every `META_TOKEN_CHECK_INTERVAL_SECONDS`
(1h), inspecting with the app token when app ID and secret are set. It exports validity, expiry,
data-access expiry and missing `META_REQUIRED_SCOPES`. Alerts fire at 7 days and 1 day before expiry, and
when the token is invalid, scopes are missing, or the check itself goes stale.
`meta_token_valid` starts as NaN, so no alert fires before the first check.

**Webhooks** (`app/webhook_dedup.py`)
- **Signatures are required.** Without `META_APP_SECRET`, deliveries are rejected with 503, so Meta
  retries until you fix it, and `/ready` fails. `META_WEBHOOK_REQUIRE_SIGNATURE=false` opts out
  explicitly.
- **Effectively-once processing.** Meta delivers at least once, so events are deduplicated *per event*:
  `msg:<wamid>`, `status:<wamid>:<status>`, `mid:<mid>`, or a content hash. The keys live in SQLite on the
  persistent volume (7-day TTL). An event is marked only after it has been durably recorded and processed,
  so a failed attempt stays eligible for redelivery. A redelivered batch processes only its new events.

**WhatsApp delivery tracking** (`app/delivery_tracker.py`) registers each accepted `wamid` and advances it
through status webhooks (`sent → delivered → read`, or `failed`). A status never moves a message backwards.
You get time-to-sent/delivered/read histograms, failures by Meta error code, a count of messages stuck
undelivered past 10 minutes, per-message status, and window stats. Failures are also recorded in the audit
log as `whatsapp.message.failed`.

**Proactive rate limiting** (`app/rate_limiter.py`) paces calls from Meta's own usage headers:
- Calls are delayed proportionally between `META_RATE_SOFT_PCT` (80) and `META_RATE_HARD_PCT` (95), and
  refused locally at the hard limit or while Meta reports `estimated_time_to_regain_access`.
- App-wide usage applies to every call. Business-use-case usage applies only to its product (a WhatsApp
  throttle doesn't block `/debug_token` or Pages).
- WhatsApp has a token bucket per phone number (80 msg/s) and per recipient (pair limit).
- Stale readings expire, so an old high reading can't lock the app out.
- Local refusals are audited (`outcome: local_rate_limited`).

**Scheduled archive verification** runs in the audit gateway every `AUDIT_VERIFY_INTERVAL_SECONDS` (15 min;
5 min in compose). It's incremental: locked versions are immutable, so each version is downloaded and
checked only once, and later runs just re-list (new versions, delete markers, vanished versions). Results go
to `audit_archive_verify_*` metrics, `GET :9102/verify/last` (`make verify-last`), and alerts
(`AuditArchiveVerifyFailed`, `…Stale`, `AuditOpenIntents`).

**Secrets** (`app/secrets.py`, `infra/app-secrets`): set `SECRETS_MANAGER_SECRET_ID` to load
`META_ACCESS_TOKEN`, `META_APP_SECRET`, `APP_API_KEYS`, `AUDIT_JOURNAL_TOKEN`, and so on from AWS Secrets
Manager. They're refreshed every `SECRETS_REFRESH_SECONDS` and applied in place without a restart. The app
and the gateway use separate secrets with separate read policies. Rotations are audited as field names plus
fingerprints; values never appear anywhere.

To rotate the journal token with zero downtime:
1. Set the gateway secret to the new token and `AUDIT_JOURNAL_TOKEN_PREVIOUS` to the old one.
2. Wait one refresh interval, then give the app the new token.
3. Wait another interval, then clear `_PREVIOUS`.

This was tested live with continuous traffic and produced no errors. Locally, LocalStack pre-creates both
secrets; enable them with `APP_SECRETS_MANAGER_SECRET_ID=meta-api-tester/app` and
`GATEWAY_SECRETS_MANAGER_SECRET_ID=meta-api-tester/audit-gateway`.

**Logs** go to Loki via Grafana Alloy (all compose services). JSON fields become `level`/`logger` labels,
and `trace_id` becomes structured metadata. Log lines link to the Jaeger trace and traces link back to
their logs. The dashboard has "Errors & warnings" and "Audit stream" log panels.

**CI** (`.github/workflows/ci.yml`):
- `test`: the unit suite.
- `config`: promtool (rules and config), amtool, compose, and Terraform fmt/validate for every
  `infra/*` module.
- `smoke`: the full stack on a runner, with load, a signed duplicate webhook, fail-closed with S3 paused,
  archive verification and all scrape targets up.
- `contract`: the live Meta tests, daily and on manual dispatch, reading secrets from a `meta-sandbox`
  environment.

**Contract tests** (`tests/contract`, `make contract`) run against the real Graph API and are skipped
unless `META_LIVE_ACCESS_TOKEN` is set. They check `/me`, token validity, scopes and expiry, Meta's error
shape (what `MetaAPIError` parses), usage-header parsing, and a readable WhatsApp phone number. Sending a
real `hello_world` template additionally needs `META_LIVE_WA_TO`.

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

**Tamper evidence:** each record's `hash = sha256(prev_hash + record)`, so any edit, deletion or
reordering breaks the chain.

**Two modes:**
- **Gateway mode** (the default in compose, and what you run in production): the audit gateway assigns
  seq, `prev_hash` and `hash` for all replicas and commits them to S3 Object Lock before the action proceeds.
  This is described below.
- **Local mode** (`AUDIT_JOURNAL_URL` empty): a single process sequences records into its local file.
  It's for development and tests only. Here `/api/audit/verify` recomputes the local chain, and a failed
  write makes `/ready` return 503.

**Identity:** without `APP_API_KEYS`, actors are self-declared (`X-Actor`) and labelled `unverified:`.
Set API keys (or put an authenticating proxy in front) when the actor must be trustworthy.

Records are also archived off-host to S3 Object Lock, below.

## Audit sequencing across replicas (`app/audit_gateway.py`)

The app is stateless and runs as N replicas behind `lb` (`APP_REPLICAS=2` by default;
`make scale N=4`). The audit chain stays **one global, gapless, hash-chained sequence** because replicas
never sequence anything themselves:

1. A replica builds an **unsequenced draft** (who/what/when plus a random `draft_id`) and sends it to the
   **audit gateway** (`POST /v2/records`).
2. The gateway gathers concurrent drafts for a few milliseconds (`AUDIT_COMMIT_WINDOW_SECONDS`, group
   commit), assigns consecutive seqs, chains them onto its head, and writes the batch as **one** locked
   object `<prefix>/blocks/<block>.jsonl` with `If-None-Match: *`.
3. Only once S3 confirms does each replica get its sequenced record back. The action proceeds, and the
   replica appends the record to its local cache `audit-<replica>.jsonl`.

**Why it can't fork, even with two gateways (split-brain):**
- A block number is a compare-and-set slot. Only one writer can create block N; the loser gets 412,
  reads the winning block, advances its head, and re-chains its drafts, which are still unsequenced, onto
  it.
- A commit whose outcome is unknown (a timeout) is resolved from S3 before the slot is reused, so an
  abandoned write that lands late is adopted into the chain, not forked.
- Retries are safe because the gateway deduplicates by `draft_id`.
- On restart, the gateway finds the head from S3 (its index is only a cache).

Measured live with 2 replicas:
- 3,664 records in one gapless chain; both replica caches matched the archive exactly.
- Commit wait p50 8 ms, p95 22 ms.
- Forced split-brain (two gateways taking writes concurrently): 200 drafts, 25 slot conflicts, 200 unique
  seqs, archive verified with no fork.

| Step | Record | If the gateway can't commit it |
|---|---|---|
| request arrives | `http.request.received` | **503, handler never runs** |
| before calling Meta | `meta.api.<method>.intent` | **503, Meta is never called** |
| after Meta answers | `meta.api.<method>` (`intent_seq` →) | response returned (the action happened); `audit_outcome_unrecorded_total` + open intent in the verifier |
| before responding | `http.request` (`received_seq` →) | response returned with `X-Audit-Outcome: unrecorded` |
| webhook / Alertmanager delivery | `webhook.meta.*`, `alert.notification` | **503, so the sender redelivers** |
| startup | `app.started` | the replica doesn't start |

**Bounded refusals:** each draft gets one total budget on the replica (`AUDIT_JOURNAL_TIMEOUT_SECONDS`,
2s) and a hard 1.5s commit deadline in the gateway. The gateway's `/ready` goes red after a failed commit,
so replicas report not-ready.

**Global view:** the gateway indexes every committed record in SQLite. On any replica, `/api/audit`
queries that index, so you see every replica's records, filterable by `replica`. `/api/audit/verify`
returns the latest archive verification plus a check of this replica's cache against the authoritative
hashes.

**What stays per replica:** the circuit breaker, proactive pacing buckets and token monitor. Divide
`WA_MESSAGES_PER_SECOND` by the replica count if you need a hard global cap. The webhook-dedup and
delivery-tracking stores are shared (a redelivery can land on any replica). That's SQLite on the shared
volume locally; use Redis or Postgres across hosts.

**Limits:** the gateway serialises commits, so throughput is roughly records-per-block ÷ S3 PUT latency;
group commit keeps this high under load. One active gateway is the normal deployment. A second one is
*safe* but slower (it pays conflict round trips), so run it as a standby rather than active-active. Without
its index, a gateway recovers by reading blocks forward from S3, so keep its state volume.

## Audit archive & verification

The blocks under `<prefix>/blocks/` **are** the archive: locked (COMPLIANCE/GOVERNANCE), SHA-256
checksummed, optionally SSE-KMS encrypted, with chain metadata (`first-seq`, `last-seq`, `first-prev-hash`,
`last-hash`, `gateway`).

The **verifier** (`make audit-verify-s3`, or `python -m app.audit_gateway verify --compare-local FILES`):
- reads every object version, reading through delete markers and reporting them
- checks each block's checksum and lock
- flags block conflicts or gaps and rebuilds the chain from seq 1
- reports records per replica and open intents
- with `--compare-local`, checks each replica cache: a cached record whose hash differs, or that isn't in
  the archive at all, means something was written on the host

The gateway also runs it **every `AUDIT_VERIFY_INTERVAL_SECONDS`**, incrementally, since locked versions
are immutable and are downloaded only once. Results are exported as metrics and at `GET :9102/verify/last`.

Alerts: `AuditGatewayDown`, `AuditGatewayCommitFailures`, `AuditJournalRefusingActions` (critical);
`AuditSequencerConflicts`, `AuditGatewayCommitSlow`, `AuditOutcomeUnrecorded`, `AuditArchiveVerifyFailed`
/ `…Stale`, and `AuditOpenIntents`.

**Local:** LocalStack enforces Object Lock (COMPLIANCE, 1 day), so version deletes and retention changes
are refused. It's **ephemeral**: `make audit-archive-reset-local` wipes it together with the gateway index.

### Production bucket (`infra/audit-bucket`, Terraform)

```bash
cd infra/audit-bucket
cp terraform.tfvars.example terraform.tfvars   # bucket name, gateway role, admins
terraform init && terraform plan
```

It creates:
- the bucket with Object Lock, versioning and default retention
- a dedicated KMS key with rotation, and a public access block
- a bucket policy that denies non-TLS access, denies writes under any other KMS key, denies
  `s3:BypassGovernanceRetention` (except optional break-glass principals), and denies
  lock/versioning/lifecycle/policy changes (except `admin_principal_arns`)
- a Glacier IR transition after 90 days
- least-privilege **gateway** (create/read blocks, list the prefix, no delete) and **verifier**
  (read-only) IAM policies
- a **CloudTrail data-event trail** on the bucket, so every read, write and delete attempt against the
  archive is itself recorded

Then set the `gateway_env` output values in `.env` (with `AUDIT_S3_ENDPOINT_URL=` empty) and give the
gateway the IAM role.

> ⚠️ `lock_mode` defaults to **GOVERNANCE** so you can validate first. **COMPLIANCE** can't be shortened
> or removed by anyone, including the AWS root account, until retention expires. You'll pay to store every
> object for the full period. Switch deliberately.

Trust boundary: the app is the author of records, so a fully compromised app can still write *false*
records (it holds the journal token). It can't remove, reorder or rewrite anything already journaled, and
it can't act without first leaving a durable intent.

## Local dev

```bash
make install && make test     # 58 tests (+6 live contract tests, opt-in), pytest + respx
make mock &                   # mock on :8081
META_GRAPH_BASE_URL=http://localhost:8081 META_ACCESS_TOKEN=x make run
```
