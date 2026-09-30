"""WhatsApp delivery tracking: correlate status webhooks with the messages we sent.

Every successful send registers its wamid. Status webhooks (sent → delivered → read, or failed) advance
that message's state. From this we export delivery/read latency, failure reasons and stuck messages.
State is in SQLite on the persistent volume, so it survives restarts, like the webhook dedup store.

Statuses can arrive out of order or be redelivered. Dedup drops exact repeats, and a status never
moves a message backwards (a late `delivered` after `read` is ignored for state but still counted).
"""
import asyncio
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from app.audit import AuditLog, AuditUnavailable
from app.metrics import (
    WA_DELIVERY_LATENCY,
    WA_FAILURES,
    WA_MESSAGES_SENT,
    WA_MESSAGES_STALE,
    WA_STATUS_EVENTS,
)

log = logging.getLogger("whatsapp.delivery")

RANK = {"accepted": 0, "sent": 1, "delivered": 2, "read": 3, "failed": 4}


class DeliveryTracker:
    def __init__(self, path: str, audit: AuditLog | None = None, stale_after_seconds: float = 600,
                 retention_days: float = 30):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.audit = audit
        self.stale_after = stale_after_seconds
        self.retention = retention_days * 86400
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("""CREATE TABLE IF NOT EXISTS messages (
            wamid TEXT PRIMARY KEY, kind TEXT, sent_at REAL, status TEXT NOT NULL, updated_at REAL NOT NULL,
            delivered_at REAL, read_at REAL, error_code TEXT, error_title TEXT, recipient_hash TEXT)""")
        self._db.execute("CREATE INDEX IF NOT EXISTS messages_status ON messages(status, sent_at)")
        self._lock = threading.Lock()
        self._task: asyncio.Task | None = None

    # ---------- outbound ----------
    def on_sent(self, wamid: str, kind: str, recipient_hash: str | None = None) -> None:
        now = time.time()
        WA_MESSAGES_SENT.labels(kind).inc()
        with self._lock:
            self._db.execute(
                "INSERT INTO messages (wamid, kind, sent_at, status, updated_at, recipient_hash) "
                "VALUES (?, ?, ?, 'accepted', ?, ?) ON CONFLICT(wamid) DO UPDATE SET kind=excluded.kind, "
                "sent_at=excluded.sent_at, recipient_hash=excluded.recipient_hash",
                (wamid, kind, now, now, recipient_hash))

    # ---------- inbound status webhooks ----------
    async def on_webhook(self, payload: dict[str, Any], new_keys: set[str]) -> None:
        for entry in payload.get("entry", []):
            for change in entry.get("changes", []):
                for st in (change.get("value") or {}).get("statuses", []) or []:
                    if f"status:{st.get('id')}:{st.get('status')}" in new_keys:
                        await self._apply_status(st)

    async def _apply_status(self, st: dict[str, Any]) -> None:
        wamid, status = st.get("id"), st.get("status", "unknown")
        ts = float(st.get("timestamp") or time.time())
        WA_STATUS_EVENTS.labels(status).inc()
        with self._lock:
            row = self._db.execute("SELECT status, sent_at FROM messages WHERE wamid=?", (wamid,)).fetchone()
            if row is None:   # sent by another system or before tracking started
                self._db.execute("INSERT INTO messages (wamid, kind, sent_at, status, updated_at) "
                                 "VALUES (?, 'unknown', NULL, 'accepted', ?)", (wamid, time.time()))
                row = ("accepted", None)
            current, sent_at = row
            if sent_at and status in ("sent", "delivered", "read"):
                WA_DELIVERY_LATENCY.labels(status).observe(max(0.0, ts - sent_at))
            if RANK.get(status, -1) <= RANK.get(current, -1) or current == "failed":
                return   # out-of-order / regression: counted above, state unchanged
            cols = {"status": status, "updated_at": time.time()}
            if status == "delivered":
                cols["delivered_at"] = ts
            elif status == "read":
                cols["read_at"] = ts
            elif status == "failed":
                err = (st.get("errors") or [{}])[0]
                cols["error_code"], cols["error_title"] = str(err.get("code")), err.get("title")
            self._db.execute(f"UPDATE messages SET {', '.join(f'{k}=?' for k in cols)} WHERE wamid=?",
                             [*cols.values(), wamid])

        if status == "failed":
            WA_FAILURES.labels(cols["error_code"], cols["error_title"] or "unknown").inc()
            if self.audit:
                try:
                    await self.audit.arecord("whatsapp.message.failed", actor="meta", resource=wamid,
                                             error_code=cols["error_code"], error_title=cols["error_title"])
                except AuditUnavailable:
                    # Propagate: the webhook returns 503 and Meta redelivers, so the failure isn't lost.
                    raise

    # ---------- queries / housekeeping ----------
    def get(self, wamid: str) -> dict[str, Any] | None:
        with self._lock:
            cur = self._db.execute("SELECT * FROM messages WHERE wamid=?", (wamid,))
            row = cur.fetchone()
            return dict(zip([c[0] for c in cur.description], row)) if row else None

    def stats(self, since_seconds: float = 3600) -> dict[str, Any]:
        since = time.time() - since_seconds
        with self._lock:
            by_status = dict(self._db.execute(
                "SELECT status, COUNT(*) FROM messages WHERE sent_at >= ? GROUP BY status", (since,)).fetchall())
            failures = self._db.execute(
                "SELECT error_code, error_title, COUNT(*) FROM messages WHERE status='failed' AND sent_at >= ? "
                "GROUP BY error_code, error_title ORDER BY 3 DESC LIMIT 10", (since,)).fetchall()
        total = sum(by_status.values())
        reached = by_status.get("delivered", 0) + by_status.get("read", 0)
        return {"window_seconds": since_seconds, "sent": total, "by_status": by_status,
                "delivery_rate": round(reached / total, 4) if total else None,
                "failure_rate": round(by_status.get("failed", 0) / total, 4) if total else None,
                "top_failures": [{"code": c, "title": t, "count": n} for c, t, n in failures],
                "stale_undelivered": self.stale_count()}

    def stale_count(self) -> int:
        cutoff = time.time() - self.stale_after
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM messages WHERE status IN ('accepted','sent') "
                                    "AND sent_at IS NOT NULL AND sent_at < ?", (cutoff,)).fetchone()[0]

    def refresh_gauges(self) -> None:
        WA_MESSAGES_STALE.set(self.stale_count())
        with self._lock:
            self._db.execute("DELETE FROM messages WHERE updated_at < ?", (time.time() - self.retention,))

    async def _loop(self) -> None:
        while True:
            try:
                self.refresh_gauges()
            except sqlite3.Error:
                log.exception("delivery gauge refresh failed")
            await asyncio.sleep(30)

    def start(self) -> None:
        self._task = asyncio.create_task(self._loop(), name="wa-delivery-tracker")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._db.close()
