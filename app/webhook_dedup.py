"""At-least-once → effectively-once for Meta webhooks.

Meta redelivers a webhook until it gets a 200 (for days, for WhatsApp), and one delivery can batch
several events. We therefore dedupe per *event*, not per HTTP delivery:

  WhatsApp message   -> msg:<wamid>
  WhatsApp status    -> status:<wamid>:<status>    (sent / delivered / read / failed are distinct events)
  Messenger / IG     -> mid:<message mid>
  anything else      -> sha256 of the canonical event JSON

Keys live in SQLite on the persistent volume, so restarts don't reopen the window, and expire after
META_WEBHOOK_DEDUP_TTL_DAYS. A key is marked only after the event was recorded and processed, so a
failed attempt stays eligible for redelivery.
"""
import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any


def _h(obj: Any) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:32]


def event_keys(payload: dict[str, Any]) -> list[dict[str, str]]:
    """Every distinct event in a delivery, as {key, kind, field}."""
    events: list[dict[str, str]] = []
    for entry in payload.get("entry", []):
        found = False
        for change in entry.get("changes", []):
            found = True
            field = change.get("field", "unknown")
            value = change.get("value", {}) or {}
            keyed = False
            for m in value.get("messages", []) or []:
                if m.get("id"):
                    events.append({"key": f"msg:{m['id']}", "kind": "message", "field": field})
                    keyed = True
            for st in value.get("statuses", []) or []:
                if st.get("id"):
                    events.append({"key": f"status:{st['id']}:{st.get('status')}", "kind": "status",
                                   "field": field})
                    keyed = True
            if not keyed:
                events.append({"key": "chg:" + _h({"entry": entry.get("id"), "field": field, "value": value}),
                               "kind": "change", "field": field})
        for ev in entry.get("messaging", []) or []:
            found = True
            mid = (ev.get("message") or {}).get("mid")
            events.append({"key": f"mid:{mid}" if mid else "ev:" + _h(ev), "kind": "messaging",
                           "field": "messaging"})
        if not found:
            events.append({"key": "entry:" + _h(entry), "kind": "entry", "field": "unknown"})
    return events


class WebhookDedup:
    def __init__(self, path: str, ttl_days: float):
        self.ttl = ttl_days * 86400
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("CREATE TABLE IF NOT EXISTS seen (key TEXT PRIMARY KEY, first_seen REAL NOT NULL)")
        self._lock = threading.Lock()
        self._writes = 0
        self.prune()

    def seen(self, keys: list[str]) -> set[str]:
        if not keys:
            return set()
        cutoff = time.time() - self.ttl
        with self._lock:
            rows = self._db.execute(
                f"SELECT key FROM seen WHERE first_seen >= ? AND key IN ({','.join('?' * len(keys))})",
                [cutoff, *keys]).fetchall()
        return {r[0] for r in rows}

    def mark(self, keys: list[str]) -> None:
        now = time.time()
        with self._lock:
            self._db.executemany("INSERT OR IGNORE INTO seen (key, first_seen) VALUES (?, ?)",
                                 [(k, now) for k in keys])
            self._writes += len(keys)
            if self._writes > 10_000:
                self._writes = 0
                self._db.execute("DELETE FROM seen WHERE first_seen < ?", (now - self.ttl,))

    def prune(self) -> None:
        with self._lock:
            self._db.execute("DELETE FROM seen WHERE first_seen < ?", (time.time() - self.ttl,))

    def close(self) -> None:
        self._db.close()
