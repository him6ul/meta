"""Append-only, hash-chained audit log.

Every record carries `prev_hash` and `hash = sha256(prev_hash + canonical_json(record))`, so any edit,
deletion or reordering of past records breaks the chain and is detected by `verify()`.
Records are also emitted to the `audit` logger so they reach log aggregation alongside app logs.

Records hold who/what/when/outcome plus identifiers (request_id, trace_id, fbtrace_id, Meta object IDs).
Payloads are stored as a SHA-256 digest + size, never verbatim, so message content (PII) and secrets
stay out of the trail while still letting you prove what was sent if you hold the original.
"""
import hashlib
import json
import logging
import os
import threading
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from opentelemetry import trace

from app.metrics import AUDIT_EVENTS, AUDIT_WRITE_FAILURES

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


class AuditLog:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.last_write_ok = True
        self._seq, self._prev_hash = self._load_tail()

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

    def record(self, action: str, *, outcome: str = "success", actor: str | None = None,
               resource: str | None = None, **details: Any) -> dict[str, Any] | None:
        ctx = request_context.get()
        span_ctx = trace.get_current_span().get_span_context()
        entry: dict[str, Any] = {
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
        try:
            with self._lock:
                entry["seq"] = self._seq + 1
                entry["prev_hash"] = self._prev_hash
                entry["hash"] = _chain_hash(self._prev_hash, entry)
                with self.path.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(entry, default=str) + "\n")
                    f.flush()
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
            stored = rec.pop("hash")
            if rec.get("prev_hash") != prev or _chain_hash(prev, rec) != stored or rec["seq"] != count + 1:
                return {"ok": False, "records_checked": count, "first_bad_seq": rec.get("seq")}
            prev, count = stored, count + 1
        return {"ok": True, "records_checked": count, "head_hash": prev}
