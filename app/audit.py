"""Append-only, hash-chained audit log.

Every record carries `prev_hash` and `hash = sha256(prev_hash + canonical_json(record))`, so any edit,
deletion or reordering of past records breaks the chain and is detected by `verify()`.
Records are also emitted to the `audit` logger so they reach log aggregation alongside app logs.

Records hold who/what/when/outcome plus identifiers (request_id, trace_id, fbtrace_id, Meta object IDs).
Payloads are stored as a SHA-256 digest + size, never verbatim, so message content (PII) and secrets
stay out of the trail while still letting you prove what was sent if you hold the original.

Gateway mode (AUDIT_JOURNAL_URL): `arecord()` sends an unsequenced draft to the audit gateway, which
sequences records from ALL app replicas into one chain and commits them to S3 Object Lock before
returning. If that fails it raises AuditUnavailable, and callers refuse the action (fail closed).
Combined with write-ahead intent records, no side effect happens without an immutable off-host record.
"""
import asyncio
import hashlib
import json
import logging
import os
import threading
import time
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from opentelemetry import trace

from app.metrics import AUDIT_EVENTS, AUDIT_JOURNAL_FAILURES, AUDIT_JOURNAL_LATENCY, AUDIT_WRITE_FAILURES

log = logging.getLogger("audit")

GENESIS_HASH = "0" * 64
SENSITIVE_KEYS = {"access_token", "appsecret_proof", "input_token", "client_secret", "api_key",
                  "x-api-key", "authorization", "hub.verify_token"}

# Who is acting in the current request; set by the HTTP middleware, read by every audit call.
request_context: ContextVar[dict[str, Any]] = ContextVar("audit_request_context", default={})


def new_request_id() -> str:
    return uuid.uuid4().hex


def digest(data: bytes | str | None) -> dict[str, Any] | None:
    if not data:
        return None
    if isinstance(data, str):
        data = data.encode()
    return {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}


def sanitize(params: dict[str, Any] | None) -> dict[str, Any]:
    return {k: ("***" if k.lower() in SENSITIVE_KEYS else v) for k, v in (params or {}).items()}


def _chain_hash(prev_hash: str, record: dict[str, Any]) -> str:
    body = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256((prev_hash + body).encode()).hexdigest()


def link_ok(prev_hash: str, record: dict[str, Any]) -> bool:
    """True if `record` correctly chains onto `prev_hash` (shared by verify() and the S3 shipper)."""
    body = {k: v for k, v in record.items() if k != "hash"}
    return body.get("prev_hash") == prev_hash and _chain_hash(prev_hash, body) == record.get("hash")


class AuditUnavailable(Exception):
    """The record could not be made durable; the caller must not perform (or acknowledge) the action."""


class GatewayClient:
    """Talks to the audit gateway, the global sequencer. A draft is durable (in an S3 Object Lock block) and
    sequenced when `append` returns."""

    def __init__(self, url: str, token: str, timeout: float = 2.0, retries: int = 2,
                 transport: httpx.AsyncBaseTransport | None = None):
        self.timeout = timeout   # total budget per record, across retries
        self.retries = retries
        self._http = httpx.AsyncClient(base_url=url.rstrip("/"), timeout=timeout, transport=transport,
                                       headers={"authorization": f"Bearer {token}"})

    async def append(self, draft: dict[str, Any]) -> dict[str, Any]:
        """Retry transient failures within ONE overall deadline. Retries are safe: the gateway dedups by
        draft_id, so a retry of a draft that did commit returns the same record."""
        deadline = time.monotonic() + self.timeout
        last_error, attempt = "unknown", 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            start = time.perf_counter()
            try:
                resp = await asyncio.wait_for(self._http.post("/v2/records", json=draft, timeout=remaining), remaining)
            except (httpx.HTTPError, asyncio.TimeoutError) as exc:
                last_error, reason = repr(exc), "unreachable"
            else:
                AUDIT_JOURNAL_LATENCY.observe(time.perf_counter() - start)
                if resp.status_code in (200, 201):
                    return resp.json()
                last_error, reason = f"{resp.status_code} {resp.text[:200]}", str(resp.status_code)
                if resp.status_code in (400, 401, 409):   # not transient: don't retry
                    AUDIT_JOURNAL_FAILURES.labels(reason).inc()
                    break
            AUDIT_JOURNAL_FAILURES.labels(reason).inc()
            if attempt >= self.retries:
                break
            await asyncio.sleep(min(0.05 * (2 ** attempt), max(0.0, deadline - time.monotonic())))
            attempt += 1
        raise AuditUnavailable(f"gateway did not commit {draft.get('action')} ({draft.get('draft_id')}): {last_error}")

    async def query(self, **params: Any) -> list[dict[str, Any]]:
        resp = await self._http.get("/v2/records", params={k: v for k, v in params.items() if v is not None})
        resp.raise_for_status()
        return resp.json()

    async def hashes(self, seqs: list[int]) -> dict[int, str]:
        resp = await self._http.post("/v2/records/hashes", json=seqs)
        resp.raise_for_status()
        return {int(k): v for k, v in resp.json().items()}

    async def last_verification(self) -> dict[str, Any] | None:
        resp = await self._http.get("/verify/last")
        return resp.json() if resp.status_code == 200 else None

    def set_token(self, token: str) -> None:
        """Called on secret rotation."""
        self._http.headers["authorization"] = f"Bearer {token}"

    async def healthy(self) -> bool:
        """Gateway /ready: up AND able to commit to S3 recently."""
        try:
            return (await self._http.get("/ready", timeout=1.0)).status_code == 200
        except httpx.HTTPError:
            return False

    async def aclose(self) -> None:
        await self._http.aclose()


class AuditLog:
    """Two modes.

    - Local (no gateway): this process assigns seq/hash and appends to a local hash-chained file.
      Single writer only; for development and tests.
    - Gateway: this process builds an *unsequenced* draft; the audit gateway assigns seq/prev_hash/hash
      across all replicas and commits it to S3 Object Lock before returning it. The local file is then a
      per-replica cache of this replica's records (non-contiguous seqs); the archive is the truth.
    """

    def __init__(self, path: str, gateway: GatewayClient | None = None, replica: str | None = None):
        self.gateway = gateway
        self.replica = replica
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.last_write_ok = True
        self._seq, self._prev_hash = self._load_tail() if gateway is None else (0, GENESIS_HASH)

    def _load_tail(self) -> tuple[int, str]:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return 0, GENESIS_HASH
        last = None
        with self.path.open("rb") as f:
            for line in f:
                if line.strip():
                    last = line
        rec = json.loads(last)
        return rec["seq"], rec["hash"]

    def _draft(self, action: str, outcome: str, actor: str | None, resource: str | None,
               details: dict[str, Any]) -> dict[str, Any]:
        ctx = request_context.get()
        span_ctx = trace.get_current_span().get_span_context()
        draft: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "outcome": outcome,
            "actor": actor or ctx.get("actor", "system"),
            "actor_ip": ctx.get("ip"),
            "user_agent": ctx.get("user_agent"),
            "request_id": ctx.get("request_id"),
            "trace_id": format(span_ctx.trace_id, "032x") if span_ctx.is_valid else None,
            "resource": resource,
            "details": {k: v for k, v in details.items() if v is not None},
        }
        if self.replica:
            draft["replica"] = self.replica
        return draft

    def _append_line(self, entry: dict[str, Any]) -> None:
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, default=str) + "\n")
            f.flush()

    def record(self, action: str, *, outcome: str = "success", actor: str | None = None,
               resource: str | None = None, **details: Any) -> dict[str, Any] | None:
        """Local mode only: sequence + append locally. Returns None if the write failed."""
        if self.gateway is not None:
            raise RuntimeError("AuditLog.record() is local-mode only; use arecord() with a gateway")
        entry = self._draft(action, outcome, actor, resource, details)
        try:
            with self._lock:
                entry["seq"] = self._seq + 1
                entry["prev_hash"] = self._prev_hash
                entry["hash"] = _chain_hash(self._prev_hash, entry)
                self._append_line(entry)
                self._seq, self._prev_hash = entry["seq"], entry["hash"]
        except OSError:
            self.last_write_ok = False
            AUDIT_WRITE_FAILURES.inc()
            log.exception("audit write failed", extra={"audit_action": action})
            return None
        self.last_write_ok = True
        AUDIT_EVENTS.labels(action, outcome).inc()
        log.info("audit", extra={"audit": entry})
        return entry

    async def arecord(self, action: str, *, outcome: str = "success", actor: str | None = None,
                      resource: str | None = None, **details: Any) -> dict[str, Any]:
        """Durably record, then return the sequenced record. Raises AuditUnavailable if it isn't durable;
        callers treat that as "don't act"."""
        if self.gateway is None:
            entry = self.record(action, outcome=outcome, actor=actor, resource=resource, **details)
            if entry is None:
                raise AuditUnavailable(f"local audit write failed for {action}")
            return entry
        draft = self._draft(action, outcome, actor, resource, details)
        draft["draft_id"] = uuid.uuid4().hex
        try:
            entry = await self.gateway.append(draft)
        except AuditUnavailable:
            log.error("audit record not committed", extra={"audit_action": action, "draft_id": draft["draft_id"]})
            raise
        try:
            with self._lock:
                self._append_line(entry)   # cache only; the committed record is already durable off-host
            self.last_write_ok = True
        except OSError:
            self.last_write_ok = False
            AUDIT_WRITE_FAILURES.inc()
            log.exception("audit cache write failed (record is committed)", extra={"seq": entry.get("seq")})
        AUDIT_EVENTS.labels(action, outcome).inc()
        log.info("audit", extra={"audit": entry})
        return entry

    async def cache_consistency(self) -> dict[str, Any]:
        """Gateway mode: check this replica's cached records against the authoritative chain."""
        cached = {r["seq"]: r["hash"] for r in self._iter()}
        if not cached:
            return {"records": 0, "mismatched_seqs": [], "unknown_to_gateway": []}
        authoritative = await self.gateway.hashes(sorted(cached)[-5000:])
        checked = sorted(cached)[-5000:]
        return {"records": len(cached), "checked": len(checked),
                "mismatched_seqs": [q for q in checked if q in authoritative and authoritative[q] != cached[q]][:50],
                "unknown_to_gateway": [q for q in checked if q not in authoritative][:50]}

    def writable(self) -> bool:
        """Used by /ready: an instance that can't record actions shouldn't receive traffic."""
        target = self.path if self.path.exists() else self.path.parent
        return self.last_write_ok and os.access(target, os.W_OK)

    def _iter(self):
        if not self.path.exists():
            return
        with self.path.open(encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    yield json.loads(line)

    def query(self, *, limit: int = 100, action: str | None = None, actor: str | None = None,
              request_id: str | None = None, outcome: str | None = None) -> list[dict[str, Any]]:
        matches = [r for r in self._iter()
                   if (action is None or r["action"] == action or r["action"].startswith(action + "."))
                   and (actor is None or r["actor"] == actor)
                   and (request_id is None or r["request_id"] == request_id)
                   and (outcome is None or r["outcome"] == outcome)]
        return matches[-limit:][::-1]

    def verify(self) -> dict[str, Any]:
        prev, count = GENESIS_HASH, 0
        for rec in self._iter():
            if not link_ok(prev, rec) or rec["seq"] != count + 1:
                return {"ok": False, "records_checked": count, "first_bad_seq": rec.get("seq")}
            prev, count = rec["hash"], count + 1
        return {"ok": True, "records_checked": count, "head_hash": prev}
