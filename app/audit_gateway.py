"""Audit gateway: the single global sequencer for the audit chain, backed by S3 Object Lock.

App replicas send *unsequenced* drafts (`POST /v2/records`). The gateway batches concurrent drafts
(group commit), assigns consecutive seqs, chains them onto the current head, and commits the batch as ONE
immutable block object `<prefix>/blocks/<block:012d>.jsonl`, written with `If-None-Match: *` (S3
conditional write) and Object Lock. Only after S3 confirms does each replica get its sequenced record back.

Why this stays correct with many app replicas, and even several gateways:
- Seqs and hashes are assigned only here, so replicas can't collide or interleave inconsistently.
- The block number is a compare-and-set slot. Two writers can't both create block N: the loser gets 412,
  reads the winning block from S3, advances its head, and re-chains its drafts (still unsequenced)
  onto it. The chain can't fork; extra gateways only cost throughput under contention.
- Drafts carry a `draft_id`: a retried draft returns the already-committed record instead of a duplicate.
- If a commit's outcome is unknown (timeout), the next commit first resolves that block number from S3,
  so an abandoned write that landed later is adopted into the chain, never overwritten or forked.

Also here: a SQLite index of every committed record (global query API for all replicas), a scheduled
incremental verifier, and the verification CLI.

  python -m app.audit_gateway run
  python -m app.audit_gateway verify [--compare-local FILE ...]
"""
import argparse
import asyncio
import base64
import hashlib
import hmac
import json
import logging
import socket
import sqlite3
import sys
import threading
import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import asynccontextmanager
from concurrent.futures import TimeoutError as FutureTimeout
from datetime import datetime, timedelta, timezone
from pathlib import Path
from queue import Empty, Queue
from typing import Any

import boto3
import uvicorn
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import Body, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from prometheus_client import Counter, Gauge, Histogram, make_asgi_app
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.audit import GENESIS_HASH, _chain_hash, link_ok

log = logging.getLogger("audit.gateway")

# ---------- metrics ----------
BLOCKS = Counter("audit_gateway_blocks_committed_total", "Blocks committed to S3 Object Lock")
RECORDS = Counter("audit_gateway_records_committed_total", "Records sequenced and committed", ["replica"])
BATCH_SIZE = Histogram("audit_gateway_batch_records", "Records per committed block",
                       buckets=(1, 2, 4, 8, 16, 32, 64, 128, 256, 512))
PUT_LATENCY = Histogram("audit_gateway_s3_put_duration_seconds", "S3 PutObject latency per block",
                        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2))
DRAFT_WAIT = Histogram("audit_gateway_draft_wait_seconds", "Draft submit -> sequenced record returned",
                       buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2))
CONFLICTS = Counter("audit_gateway_sequencer_conflicts_total",
                    "Block slots already taken by another writer (or an adopted abandoned write)")
REJECTED = Counter("audit_gateway_drafts_rejected_total", "Drafts not sequenced", ["reason"])
HEAD_SEQ = Gauge("audit_gateway_head_seq", "Highest committed seq")
HEAD_BLOCK = Gauge("audit_gateway_head_block", "Highest committed block number")
for _r in ("unauthorized", "malformed", "deadline", "s3_error"):
    REJECTED.labels(_r)


class GatewaySettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    audit_s3_bucket: str = ""
    audit_s3_prefix: str = "audit/meta-api-tester"
    audit_s3_endpoint_url: str = ""          # set for MinIO/LocalStack; empty = AWS
    audit_s3_region: str = "us-east-1"
    audit_s3_lock_mode: str = "GOVERNANCE"   # COMPLIANCE in production
    audit_s3_retention_days: int = 365
    audit_s3_kms_key_id: str = ""
    audit_journal_token: str = ""            # bearer token replicas present
    audit_journal_token_previous: str = ""   # also accepted during a rotation
    audit_commit_window_seconds: float = 0.005    # gather concurrent drafts this long into one block
    audit_max_block_records: int = 500
    audit_commit_deadline_seconds: float = 1.5    # keep below the app's journal budget
    audit_gateway_state_dir: str = "data/gateway"
    audit_gateway_port: int = 9102
    audit_verify_interval_seconds: float = 900
    secrets_manager_secret_id: str = ""
    secrets_manager_region: str = "us-east-1"
    secrets_manager_endpoint_url: str = ""
    secrets_refresh_seconds: float = 300


def audit_event(action: str, stream=None, **details: Any) -> None:
    """The gateway's own operational actions, as JSON lines (stdout; stderr in CLI mode)."""
    print(json.dumps({"audit": True, "ts": datetime.now(timezone.utc).isoformat(), "service": "audit-gateway",
                      "host": socket.gethostname(), "action": action, **details}, default=str),
          file=stream or sys.stdout, flush=True)


def make_s3(s: GatewaySettings):
    # Tight timeouts: commits are on the synchronous path of every action.
    cfg = Config(retries={"mode": "standard", "max_attempts": 2}, connect_timeout=1, read_timeout=2,
                 s3={"addressing_style": "path"} if s.audit_s3_endpoint_url else None)
    return boto3.client("s3", endpoint_url=s.audit_s3_endpoint_url or None, region_name=s.audit_s3_region,
                        config=cfg)


def canonical_line(record: dict[str, Any]) -> bytes:
    return (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()


class SlotTaken(Exception):
    pass


class StoreUnavailable(Exception):
    pass


# ---------- S3 block store ----------
class BlockStore:
    def __init__(self, settings: GatewaySettings, s3):
        self.s, self.s3 = settings, s3
        self._pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="block-put")

    def key(self, block: int) -> str:
        return f"{self.s.audit_s3_prefix.strip('/')}/blocks/{block:012d}.jsonl"

    def put(self, block: int, body: bytes, records: list[dict], gateway_id: str) -> str | None:
        """Create block `block` or raise SlotTaken / StoreUnavailable. Bounded by a hard deadline."""
        params: dict[str, Any] = dict(
            Bucket=self.s.audit_s3_bucket, Key=self.key(block), Body=body, ContentType="application/x-ndjson",
            IfNoneMatch="*",
            ContentMD5=base64.b64encode(hashlib.md5(body).digest()).decode(), ChecksumAlgorithm="SHA256",
            ObjectLockMode=self.s.audit_s3_lock_mode,
            ObjectLockRetainUntilDate=datetime.now(timezone.utc) + timedelta(days=self.s.audit_s3_retention_days),
            Metadata={"block": str(block), "first-seq": str(records[0]["seq"]), "last-seq": str(records[-1]["seq"]),
                      "first-prev-hash": records[0]["prev_hash"], "last-hash": records[-1]["hash"],
                      "sha256": hashlib.sha256(body).hexdigest(), "gateway": gateway_id},
        )
        if self.s.audit_s3_kms_key_id:
            params.update(ServerSideEncryption="aws:kms", SSEKMSKeyId=self.s.audit_s3_kms_key_id)
        start = time.perf_counter()
        try:
            resp = self._pool.submit(self.s3.put_object, **params).result(timeout=self.s.audit_commit_deadline_seconds)
        except FutureTimeout:
            raise StoreUnavailable("s3 put deadline exceeded")
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") in ("PreconditionFailed", "412", "ConditionalRequestConflict"):
                raise SlotTaken(block)
            raise StoreUnavailable(f"s3 error {e.response.get('Error', {}).get('Code')}")
        except BotoCoreError as e:
            raise StoreUnavailable(f"s3 unreachable: {type(e).__name__}")
        finally:
            PUT_LATENCY.observe(time.perf_counter() - start)
        return resp.get("VersionId")

    def get(self, block: int) -> tuple[list[dict], str] | None:
        """(records, sha256) of an existing block, or None if the slot is free."""
        try:
            got = self._pool.submit(self.s3.get_object, Bucket=self.s.audit_s3_bucket, Key=self.key(block)).result(
                timeout=self.s.audit_commit_deadline_seconds)
        except FutureTimeout:
            raise StoreUnavailable("s3 get deadline exceeded")
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") in ("NoSuchKey", "404", "NotFound"):
                return None
            raise StoreUnavailable(f"s3 error {e.response.get('Error', {}).get('Code')}")
        except BotoCoreError as e:
            raise StoreUnavailable(f"s3 unreachable: {type(e).__name__}")
        body = got["Body"].read()
        return [json.loads(x) for x in body.splitlines() if x.strip()], hashlib.sha256(body).hexdigest()


# ---------- index (global query + recovery hint; a cache, S3 is the truth) ----------
class RecordIndex:
    COLS = ("seq", "block", "ts", "action", "outcome", "actor", "replica", "request_id", "resource", "draft_id")

    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("""CREATE TABLE IF NOT EXISTS records (seq INTEGER PRIMARY KEY, block INTEGER NOT NULL,
            ts TEXT, action TEXT, outcome TEXT, actor TEXT, replica TEXT, request_id TEXT, resource TEXT,
            draft_id TEXT UNIQUE, hash TEXT NOT NULL, json TEXT NOT NULL)""")
        for col in ("action", "actor", "request_id", "replica"):
            self._db.execute(f"CREATE INDEX IF NOT EXISTS records_{col} ON records({col})")
        self._lock = threading.Lock()

    def add(self, records: list[dict], block: int) -> None:
        with self._lock:
            self._db.executemany(
                "INSERT OR IGNORE INTO records VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                [(r["seq"], block, r.get("ts"), r.get("action"), r.get("outcome"), r.get("actor"), r.get("replica"),
                  r.get("request_id"), r.get("resource"), r.get("draft_id"), r["hash"], json.dumps(r))
                 for r in records])

    def head(self) -> tuple[int, str, int]:
        with self._lock:
            row = self._db.execute("SELECT seq, hash, block FROM records ORDER BY seq DESC LIMIT 1").fetchone()
        return (row[0], row[1], row[2]) if row else (0, GENESIS_HASH, 0)

    def by_draft(self, draft_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute("SELECT json FROM records WHERE draft_id=?", (draft_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def get(self, seq: int) -> dict | None:
        with self._lock:
            row = self._db.execute("SELECT json FROM records WHERE seq=?", (seq,)).fetchone()
        return json.loads(row[0]) if row else None

    def hashes(self, seqs: list[int]) -> dict[int, str]:
        out: dict[int, str] = {}
        with self._lock:
            for i in range(0, len(seqs), 500):
                chunk = seqs[i:i + 500]
                out.update(self._db.execute(f"SELECT seq, hash FROM records WHERE seq IN ({','.join('?' * len(chunk))})",
                                            chunk).fetchall())
        return out

    def query(self, *, limit: int = 100, action: str | None = None, actor: str | None = None,
              request_id: str | None = None, outcome: str | None = None, replica: str | None = None) -> list[dict]:
        where, args = [], []
        if action:
            where.append("(action = ? OR action LIKE ?)")
            args += [action, action + ".%"]
        for col, val in (("actor", actor), ("request_id", request_id), ("outcome", outcome), ("replica", replica)):
            if val:
                where.append(f"{col} = ?")
                args.append(val)
        sql = "SELECT json FROM records" + (" WHERE " + " AND ".join(where) if where else "") + \
              " ORDER BY seq DESC LIMIT ?"
        with self._lock:
            return [json.loads(r[0]) for r in self._db.execute(sql, [*args, min(limit, 1000)]).fetchall()]

    def close(self) -> None:
        self._db.close()


# ---------- sequencer ----------
class SequencerUnavailable(Exception):
    pass


class _Pending:
    __slots__ = ("draft", "future", "deadline", "submitted")

    def __init__(self, draft: dict, deadline: float):
        self.draft, self.deadline, self.submitted = draft, deadline, time.monotonic()
        self.future: Future = Future()


class Sequencer:
    def __init__(self, settings: GatewaySettings, store: BlockStore, index: RecordIndex, gateway_id: str):
        self.s, self.store, self.index, self.gateway_id = settings, store, index, gateway_id
        self.head_seq, self.head_hash, self.head_block = index.head()
        self.uncertain = False          # last commit outcome unknown -> resolve before reusing the slot
        self.last_ok = 0.0
        self.last_error = 0.0
        self._queue: Queue[_Pending] = Queue()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # ----- recovery -----
    def _adopt(self, block: int, records: list[dict]) -> None:
        """Advance the head over a block someone else (or an abandoned write of ours) committed."""
        if not records or records[0]["seq"] != self.head_seq + 1 or not link_ok(self.head_hash, records[0]):
            raise RuntimeError(f"block {block} does not extend head {self.head_seq}: archive is inconsistent")
        prev = self.head_hash
        for r in records:
            if not link_ok(prev, r):
                raise RuntimeError(f"block {block} has an internal chain break at seq {r.get('seq')}")
            prev = r["hash"]
        self.index.add(records, block)
        self.head_seq, self.head_hash, self.head_block = records[-1]["seq"], records[-1]["hash"], block
        HEAD_SEQ.set(self.head_seq)
        HEAD_BLOCK.set(self.head_block)

    def catch_up(self) -> int:
        """Probe forward from the local head until the next block slot is free. Returns blocks adopted."""
        adopted = 0
        while True:
            found = self.store.get(self.head_block + 1)
            if found is None:
                self.uncertain = False
                return adopted
            self._adopt(self.head_block + 1, found[0])
            adopted += 1

    # ----- API -----
    def submit(self, draft: dict, timeout: float) -> Future:
        p = _Pending(draft, time.monotonic() + timeout)
        self._queue.put(p)
        return p.future

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="sequencer", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    # ----- commit loop -----
    def _take_batch(self) -> list[_Pending]:
        try:
            first = self._queue.get(timeout=0.2)
        except Empty:
            return []
        batch = [first]
        window_end = time.monotonic() + self.s.audit_commit_window_seconds
        while len(batch) < self.s.audit_max_block_records:
            remaining = window_end - time.monotonic()
            if remaining <= 0:
                break
            try:
                batch.append(self._queue.get(timeout=remaining))
            except Empty:
                break
        return batch

    def _chain(self, drafts: list[dict]) -> list[dict]:
        records, prev, seq = [], self.head_hash, self.head_seq
        for d in drafts:
            seq += 1
            rec = {**d, "seq": seq, "prev_hash": prev}
            rec["hash"] = _chain_hash(prev, rec)
            records.append(rec)
            prev = rec["hash"]
        return records

    def _fail(self, batch: list[_Pending], reason: str) -> None:
        REJECTED.labels(reason).inc(len(batch))
        for p in batch:
            if not p.future.done():
                p.future.set_exception(SequencerUnavailable(reason))

    def _run(self) -> None:
        while not self._stop.is_set():
            batch = self._take_batch()
            if not batch:
                continue
            # Idempotent retries: a draft already committed returns its record.
            live = []
            for p in batch:
                existing = self.index.by_draft(p.draft["draft_id"])
                if existing is not None:
                    p.future.set_result(existing)
                else:
                    live.append(p)
            try:
                self._commit(live)
            except Exception:   # never let the loop die
                log.exception("sequencer commit failed")
                self._fail([p for p in live if not p.future.done()], "s3_error")

    def _commit(self, batch: list[_Pending]) -> None:
        while batch:
            now = time.monotonic()
            expired = [p for p in batch if p.deadline <= now]
            if expired:
                self._fail(expired, "deadline")
                batch = [p for p in batch if p.deadline > now]
                if not batch:
                    return
            try:
                if self.uncertain:
                    self.catch_up()   # resolve the unknown slot before writing anything new
                records = self._chain([p.draft for p in batch])
                body = b"".join(canonical_line(r) for r in records)
                block = self.head_block + 1
                self.store.put(block, body, records, self.gateway_id)
            except SlotTaken:
                CONFLICTS.inc()
                found = self.store.get(block)
                if found is not None and found[1] == hashlib.sha256(body).hexdigest():
                    pass   # our own earlier attempt landed: treat as committed
                else:
                    audit_event("audit.sequencer.conflict", block=block, head_seq=self.head_seq)
                    if found is not None:
                        self._adopt(block, found[0])
                    self.catch_up()
                    continue   # re-chain the still-unsequenced drafts onto the new head
            except StoreUnavailable as exc:
                self.uncertain = True
                self.last_error = time.time()
                log.error("block commit failed: %s", exc)
                self._fail(batch, "s3_error")
                return
            # committed
            self.index.add(records, block)
            self.head_seq, self.head_hash, self.head_block = records[-1]["seq"], records[-1]["hash"], block
            self.last_ok = time.time()
            HEAD_SEQ.set(self.head_seq)
            HEAD_BLOCK.set(block)
            BLOCKS.inc()
            BATCH_SIZE.observe(len(records))
            for p, r in zip(batch, records):
                RECORDS.labels(r.get("replica") or "unknown").inc()
                DRAFT_WAIT.observe(time.monotonic() - p.submitted)
                p.future.set_result(r)
            return

    def degraded(self) -> bool:
        return self.last_error > self.last_ok and time.time() - self.last_error < 30


# ---------- verification ----------
_LINK_FIELDS = ("intent_seq", "received_seq")


def _slim(rec: dict[str, Any]) -> dict[str, Any]:
    details = rec.get("details") or {}
    return {"seq": rec["seq"], "hash": rec.get("hash"), "prev_hash": rec.get("prev_hash"),
            "self_ok": link_ok(rec.get("prev_hash"), rec), "action": rec.get("action", ""), "ts": rec.get("ts"),
            "resource": rec.get("resource"), "replica": rec.get("replica"),
            "details": {k: details[k] for k in _LINK_FIELDS if k in details}}


def _load_version(s3, bucket: str, key: str, version_id: str) -> dict[str, Any]:
    got = s3.get_object(Bucket=bucket, Key=key, VersionId=version_id)
    body = got["Body"].read()
    return {"key": key, "block": int(key.rsplit("/", 1)[1].split(".")[0]),
            "sha_ok": got.get("Metadata", {}).get("sha256") == hashlib.sha256(body).hexdigest(),
            "lock_mode": got.get("ObjectLockMode"), "until": got.get("ObjectLockRetainUntilDate"),
            "records": [_slim(json.loads(x)) for x in body.splitlines() if x.strip()]}


def verify_archive(settings: GatewaySettings, s3=None, compare_local: list[str] | None = None,
                   cache: dict[str, dict] | None = None) -> dict[str, Any]:
    """Logical check of the whole archive. `cache` (version_id -> parsed block) makes reruns incremental:
    Object Lock versions are immutable, so each is downloaded and hash-checked once."""
    s3 = s3 or make_s3(settings)
    cache = cache if cache is not None else {}
    bucket = settings.audit_s3_bucket
    prefix = settings.audit_s3_prefix.strip("/") + "/blocks/"
    now = datetime.now(timezone.utc)
    report: dict[str, Any] = {"verified_at": now.isoformat(), "bucket": bucket, "prefix": prefix, "objects": 0,
                              "fetched": 0, "delete_markers": [],
                              "unlocked_objects": [], "checksum_mismatches": [], "block_conflicts": [],
                              "record_conflicts": [], "warnings": []}
    blocks: dict[int, dict] = {}
    by_seq: dict[int, dict] = {}
    live: set[str] = set()

    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket, Prefix=prefix):
        for m in page.get("DeleteMarkers", []):
            report["delete_markers"].append({"key": m["Key"], "version_id": m.get("VersionId"), "at": m.get("LastModified")})
        for obj in page.get("Versions", []):
            vid = obj["VersionId"]
            live.add(vid)
            report["objects"] += 1
            entry = cache.get(vid)
            if entry is None:
                entry = cache[vid] = _load_version(s3, bucket, obj["Key"], vid)
                report["fetched"] += 1
            if not entry["sha_ok"]:
                report["checksum_mismatches"].append(entry["key"])
            if not entry["lock_mode"] or entry["until"] is None:
                report["unlocked_objects"].append({"key": entry["key"], "reason": "no retention"})
            elif entry["until"] <= now:
                report["unlocked_objects"].append({"key": entry["key"], "reason": "retention expired"})
            if entry["block"] in blocks:   # If-None-Match makes this impossible without a bypass
                report["block_conflicts"].append(entry["key"])
                continue
            blocks[entry["block"]] = entry
            for r in entry["records"]:
                if r["seq"] in by_seq and by_seq[r["seq"]]["hash"] != r["hash"]:
                    report["record_conflicts"].append(r["seq"])
                by_seq.setdefault(r["seq"], r)
    for vid in set(cache) - live:
        report["warnings"].append(f"previously verified version disappeared: {cache[vid]['key']}")

    head_block = max(blocks, default=0)
    report["block_gaps"] = [b for b in range(1, head_block + 1) if b not in blocks][:50]

    prev, first_bad = GENESIS_HASH, None
    head = max(by_seq, default=0)
    for seq in range(1, head + 1):
        r = by_seq.get(seq)
        if r is None or not r["self_ok"] or r["prev_hash"] != prev:
            first_bad = seq
            break
        prev = r["hash"]
    by_replica: dict[str, int] = {}
    for r in by_seq.values():
        by_replica[r.get("replica") or "unknown"] = by_replica.get(r.get("replica") or "unknown", 0) + 1
    report.update(blocks=len(blocks), head_block=head_block, records=len(by_seq), head_seq=head,
                  head_hash=by_seq[head]["hash"] if head else None, first_bad_seq=first_bad,
                  records_by_replica=by_replica)

    done = {r["details"].get(k) for r in by_seq.values() for k in _LINK_FIELDS}
    cutoff = now - timedelta(minutes=5)
    open_intents = [{"seq": q, "action": r["action"], "resource": r["resource"], "replica": r.get("replica"), "ts": r["ts"]}
                    for q, r in sorted(by_seq.items())
                    if (r["action"].endswith(".intent") or r["action"] == "http.request.received")
                    and q not in done and datetime.fromisoformat(r["ts"]) < cutoff]
    report["open_intents"] = open_intents[:50]
    report["open_intent_count"] = len(open_intents)
    if open_intents:
        report["warnings"].append(f"{len(open_intents)} durable intents have no recorded outcome")

    if compare_local:
        # Replica caches only ever contain records the gateway returned, so anything else was written on the host.
        local = {"files": 0, "records": 0, "mismatched_seqs": [], "not_in_archive": []}
        for path in compare_local:
            local["files"] += 1
            with open(path, encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    rec = json.loads(line)
                    local["records"] += 1
                    archived = by_seq.get(rec.get("seq"))
                    if archived is None:
                        local["not_in_archive"].append({"file": Path(path).name, "seq": rec.get("seq")})
                    elif archived["hash"] != rec.get("hash"):
                        local["mismatched_seqs"].append(rec["seq"])
        local["not_in_archive"] = local["not_in_archive"][:50]
        local["mismatched_seqs"] = local["mismatched_seqs"][:50]
        report["local"] = local

    report["findings"] = {
        "delete_markers": len(report["delete_markers"]), "unlocked_objects": len(report["unlocked_objects"]),
        "checksum_mismatches": len(report["checksum_mismatches"]), "block_conflicts": len(report["block_conflicts"]),
        "record_conflicts": len(report["record_conflicts"]), "block_gaps": len(report["block_gaps"]),
        "chain_break": int(bool(first_bad)),
        "local_mismatches": len(report["local"]["mismatched_seqs"]) if compare_local else 0,
        "local_not_in_archive": len(report["local"]["not_in_archive"]) if compare_local else 0,
    }
    report["ok"] = not any(report["findings"].values())
    return report


VERIFY_OK = Gauge("audit_archive_verify_ok", "1 if the last scheduled archive verification passed")
VERIFY_LAST_RUN = Gauge("audit_archive_verify_last_run_timestamp_seconds", "Last completed verification")
VERIFY_DURATION = Gauge("audit_archive_verify_duration_seconds", "Duration of the last verification")
VERIFY_FINDINGS = Gauge("audit_archive_verify_findings", "Findings from the last verification", ["check"])
VERIFY_OPEN_INTENTS = Gauge("audit_archive_open_intents", "Durable intents >5 min old with no outcome")
VERIFY_FETCHED = Counter("audit_archive_verify_objects_fetched_total", "Block versions downloaded by the verifier")
VERIFY_ERRORS = Counter("audit_archive_verify_errors_total", "Verification runs that errored")


class ScheduledVerifier:
    def __init__(self, settings: GatewaySettings, s3=None):
        self.s, self.s3 = settings, s3 or make_s3(settings)
        self.cache: dict[str, dict] = {}
        self.last_report: dict[str, Any] | None = None

    def run_once(self) -> dict[str, Any]:
        start = time.monotonic()
        report = verify_archive(self.s, s3=self.s3, cache=self.cache)
        VERIFY_DURATION.set(time.monotonic() - start)
        VERIFY_LAST_RUN.set(time.time())
        VERIFY_OK.set(1 if report["ok"] else 0)
        VERIFY_FETCHED.inc(report["fetched"])
        VERIFY_OPEN_INTENTS.set(report["open_intent_count"])
        for check, n in report["findings"].items():
            VERIFY_FINDINGS.labels(check).set(n)
        audit_event("audit.archive.verified", ok=report["ok"], head_seq=report["head_seq"], blocks=report["blocks"],
                    fetched=report["fetched"], findings={k: v for k, v in report["findings"].items() if v},
                    open_intents=report["open_intent_count"])
        self.last_report = report
        return report

    def run_forever(self) -> None:
        time.sleep(min(60, self.s.audit_verify_interval_seconds))
        while True:
            try:
                self.run_once()
            except Exception:
                VERIFY_ERRORS.inc()
                log.exception("scheduled verification failed")
            time.sleep(self.s.audit_verify_interval_seconds)


# ---------- HTTP API ----------
RESERVED = {"seq", "prev_hash", "hash"}


def create_gateway(settings: GatewaySettings, s3=None, verifier: ScheduledVerifier | None = None,
                   gateway_id: str | None = None) -> FastAPI:
    s3 = s3 or make_s3(settings)
    state = Path(settings.audit_gateway_state_dir)
    index = RecordIndex(str(state / "index.sqlite"))
    sequencer = Sequencer(settings, BlockStore(settings, s3), index, gateway_id or socket.gethostname())
    sequencer.catch_up()   # the index is a cache: S3 decides where the head is
    sequencer.start()
    audit_event("audit.gateway.started", head_seq=sequencer.head_seq, head_block=sequencer.head_block,
                bucket=settings.audit_s3_bucket, lock_mode=settings.audit_s3_lock_mode)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        sequencer.stop()

    app = FastAPI(title="Audit gateway", docs_url=None, redoc_url=None, lifespan=lifespan)
    app.state.sequencer, app.state.index = sequencer, index
    app.mount("/metrics", make_asgi_app())

    def authorize(authorization: str) -> None:
        accepted = [t for t in (settings.audit_journal_token, settings.audit_journal_token_previous) if t]
        if not any([hmac.compare_digest(authorization, f"Bearer {t}") for t in accepted]):
            REJECTED.labels("unauthorized").inc()
            raise HTTPException(status_code=401, detail="unauthorized")

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/ready")
    def ready():
        degraded = sequencer.degraded()
        return JSONResponse(status_code=503 if degraded else 200,
                            content={"ready": not degraded, "head_seq": sequencer.head_seq,
                                     "head_block": sequencer.head_block, "uncertain": sequencer.uncertain})

    @app.post("/v2/records", status_code=201)
    async def append(draft: dict = Body(...), authorization: str = Header("")):
        authorize(authorization)
        if not isinstance(draft.get("action"), str) or not isinstance(draft.get("draft_id"), str) or RESERVED & draft.keys():
            REJECTED.labels("malformed").inc()
            raise HTTPException(status_code=400, detail="draft must have action + draft_id and no seq/prev_hash/hash")
        fut = sequencer.submit(draft, settings.audit_commit_deadline_seconds)
        try:
            return await asyncio.wait_for(asyncio.wrap_future(fut), settings.audit_commit_deadline_seconds + 0.2)
        except (SequencerUnavailable, asyncio.TimeoutError) as exc:
            raise HTTPException(status_code=503, detail=f"not committed: {exc}")

    @app.get("/v2/records")
    def query(authorization: str = Header(""), limit: int = 100, action: str | None = None, actor: str | None = None,
              request_id: str | None = None, outcome: str | None = None, replica: str | None = None):
        authorize(authorization)
        return index.query(limit=limit, action=action, actor=actor, request_id=request_id, outcome=outcome,
                           replica=replica)

    @app.post("/v2/records/hashes")
    def hashes(seqs: list[int] = Body(...), authorization: str = Header("")):
        """For replicas checking their local cache against the authoritative chain."""
        authorize(authorization)
        return {str(k): v for k, v in index.hashes(seqs[:5000]).items()}

    @app.get("/v2/head")
    def head():
        return {"seq": sequencer.head_seq, "hash": sequencer.head_hash, "block": sequencer.head_block}

    @app.get("/verify/last")
    def last_verification():
        if verifier is None or verifier.last_report is None:
            raise HTTPException(status_code=404, detail="no verification has run yet")
        return JSONResponse(content=json.loads(json.dumps(verifier.last_report, default=str)))

    return app


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format='{"level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}')
    p = argparse.ArgumentParser(prog="audit_gateway")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("run")
    v = sub.add_parser("verify")
    v.add_argument("--compare-local", nargs="*", default=None, help="replica cache files to check against the archive")
    args = p.parse_args(argv)
    settings = GatewaySettings()
    if not settings.audit_s3_bucket:
        print("AUDIT_S3_BUCKET is required", file=sys.stderr)
        return 2
    if settings.secrets_manager_secret_id:
        from app.secrets import GATEWAY_SECRET_FIELDS, SecretsError, SecretsLoader
        loader = SecretsLoader(settings, settings.secrets_manager_secret_id, GATEWAY_SECRET_FIELDS,
                               region=settings.secrets_manager_region, endpoint_url=settings.secrets_manager_endpoint_url,
                               on_change=lambda changed: audit_event(
                                   "secrets.rotated", stream=None if args.cmd == "run" else sys.stderr,
                                   fields=sorted(changed), fingerprints=changed))
        loader.load()

        def refresh_forever():
            while True:
                time.sleep(settings.secrets_refresh_seconds)
                try:
                    loader.load()
                except SecretsError as exc:
                    log.error("secrets refresh failed: %s", exc)

        if args.cmd == "run" and settings.secrets_refresh_seconds > 0:
            threading.Thread(target=refresh_forever, name="secrets-refresh", daemon=True).start()
    if args.cmd == "run":
        s3 = make_s3(settings)
        verifier = None
        if settings.audit_verify_interval_seconds > 0:
            verifier = ScheduledVerifier(settings, s3=s3)
            threading.Thread(target=verifier.run_forever, name="archive-verifier", daemon=True).start()
        uvicorn.run(create_gateway(settings, s3=s3, verifier=verifier), host="0.0.0.0",
                    port=settings.audit_gateway_port, log_level="warning")
        return 0
    report = verify_archive(settings, compare_local=args.compare_local)
    audit_event("audit.archive.verified", stream=sys.stderr, ok=report["ok"], head_seq=report["head_seq"],
                blocks=report["blocks"], findings={k: v for k, v in report["findings"].items() if v})
    print(json.dumps(report, indent=2, default=str))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
