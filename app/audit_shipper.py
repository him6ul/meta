"""Audit gateway + shipper: durable S3 Object Lock (WORM) storage for the hash-chained audit log.

Two write paths, both into the same locked bucket:
- **Journal (synchronous).** `POST /v1/journal`. The app sends every record *before* it proceeds and
  waits for this service to write it as `<prefix>/journal/<seq>.json` (conditional write: an existing seq
  can never be overwritten). This closes the window between an action and its off-host record.
- **Segments (batched).** The shipper loop tails the local file and writes compact, verifier-friendly
  segments, and detects any local rewrite of history.

Runs as a sidecar with its own S3 credentials and a read-only view of the audit log, so the app
never holds credentials that could alter the archive.

  python -m app.audit_shipper run                         # gateway (:9102) + segment shipper
  python -m app.audit_shipper verify [--compare-local F]  # audit the archive

Each segment is an immutable object `<prefix>/YYYY/MM/DD/<first_seq>-<last_seq>.jsonl` written with
ObjectLockMode + RetainUntilDate, SHA-256 checksum and chain metadata (first prev_hash / last hash),
so the archive can be verified end-to-end without trusting the host that produced it.

Safety rules:
- Nothing is shipped unless it chains onto the last shipped hash. A break halts shipping
  (`audit_ship_halted=1`, critical alert) rather than archiving a forged history.
- If the local file no longer matches what was already shipped (truncated, rewritten or replaced),
  shipping halts too. S3 is the source of truth; the divergence itself is the evidence.
- State (byte offset, last seq/hash) only advances after S3 confirms the write. An object that already
  exists for a segment is checked by SHA-256, never overwritten.
"""
import argparse
import base64
import hashlib
import hmac
import json
import logging
import os
import socket
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import threading
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout

import boto3
import uvicorn
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import Body, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from prometheus_client import Counter, Gauge, Histogram, make_asgi_app
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.audit import GENESIS_HASH, link_ok

log = logging.getLogger("audit.shipper")

SHIPPED_RECORDS = Counter("audit_ship_records_total", "Audit records archived to S3")
SEGMENTS = Counter("audit_ship_segments_total", "Segment upload attempts", ["outcome"])
LAST_SUCCESS = Gauge("audit_ship_last_success_timestamp_seconds", "Unix time of last successful upload")
SHIPPED_SEQ = Gauge("audit_ship_last_shipped_seq", "Highest audit seq durably archived")
SOURCE_SEQ = Gauge("audit_ship_source_seq", "Highest audit seq seen in the local log")
LAG = Gauge("audit_ship_lag_records", "Records written locally but not yet archived")
HALTED = Gauge("audit_ship_halted", "1 when shipping stopped because the local chain diverged")
JOURNAL_WRITES = Counter("audit_gateway_journal_writes_total", "Journal write requests", ["outcome"])
for _outcome in ("success", "failure", "reused"):
    SEGMENTS.labels(_outcome)
JOURNAL_S3_LATENCY = Histogram("audit_gateway_s3_put_duration_seconds", "S3 PutObject latency for journal records",
                               buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2))


class ShipperSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    audit_log_path: str = "data/audit.jsonl"
    audit_shipper_state_path: str = "data/shipper-state.json"
    audit_s3_bucket: str = ""
    audit_s3_prefix: str = "audit/meta-api-tester"
    audit_s3_endpoint_url: str = ""          # set for MinIO/localstack; empty = AWS
    audit_s3_region: str = "us-east-1"
    audit_s3_lock_mode: str = "GOVERNANCE"   # COMPLIANCE in production: nobody, incl. root, can shorten it
    audit_s3_retention_days: int = 365
    audit_s3_journal_retention_days: int | None = None  # defaults to audit_s3_retention_days
    audit_journal_token: str = ""            # bearer token the app must present to the gateway
    audit_journal_token_previous: str = ""   # also accepted during a rotation
    secrets_manager_secret_id: str = ""
    secrets_manager_region: str = "us-east-1"
    secrets_manager_endpoint_url: str = ""
    secrets_refresh_seconds: float = 300
    audit_journal_put_timeout_seconds: float = 1.5  # hard deadline; keep below the app's journal budget
    audit_s3_kms_key_id: str = ""            # SSE-KMS key; empty = bucket default encryption
    audit_ship_batch_max_records: int = 500
    audit_ship_flush_seconds: float = 10.0
    audit_ship_poll_seconds: float = 1.0
    audit_ship_metrics_port: int = 9102
    audit_verify_interval_seconds: float = 900   # scheduled archive verification (0 = off)


@dataclass
class ShipState:
    offset: int = 0              # byte offset just past the last shipped line
    last_seq: int = 0
    last_hash: str = GENESIS_HASH


class HaltShipping(Exception):
    pass


def audit_event(action: str, stream=None, **details: Any) -> None:
    """The shipper's own actions are audited as JSON lines on stdout (it can't write the app's log)."""
    print(json.dumps({"audit": True, "ts": datetime.now(timezone.utc).isoformat(),
                      "service": "audit-shipper", "host": socket.gethostname(), "action": action,
                      **details}, default=str), file=stream or sys.stdout, flush=True)


def make_s3(s: ShipperSettings):
    # Tight timeouts: the journal path is synchronous and must fail fast inside the app's budget.
    cfg = Config(retries={"mode": "standard", "max_attempts": 2}, connect_timeout=1, read_timeout=2,
                 s3={"addressing_style": "path"} if s.audit_s3_endpoint_url else None)
    return boto3.client("s3", endpoint_url=s.audit_s3_endpoint_url or None,
                        region_name=s.audit_s3_region, config=cfg)


class Shipper:
    def __init__(self, settings: ShipperSettings, s3=None):
        self.s = settings
        self.s3 = s3 or make_s3(settings)
        self.source = Path(settings.audit_log_path)
        self.state_path = Path(settings.audit_shipper_state_path)
        self.state = self._load_state()
        self.halt_reason: str | None = None
        SHIPPED_SEQ.set(self.state.last_seq)
        HALTED.set(0)

    # ---------- state ----------
    def _load_state(self) -> ShipState:
        if self.state_path.exists():
            return ShipState(**json.loads(self.state_path.read_text()))
        return ShipState()

    def _save_state(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(asdict(self.state)))
        os.replace(tmp, self.state_path)  # atomic: never a half-written checkpoint

    def _halt(self, reason: str, **details: Any) -> None:
        self.halt_reason = reason
        HALTED.set(1)
        log.critical("audit shipping halted: %s", reason)
        audit_event("audit.shipping.halted", reason=reason, last_shipped_seq=self.state.last_seq,
                    last_shipped_hash=self.state.last_hash, **details)
        raise HaltShipping(reason)

    # ---------- source checks ----------
    def check_source_matches_shipped(self) -> None:
        """The line ending at our checkpoint must still be the record we shipped."""
        if self.state.offset == 0:
            return
        size = self.source.stat().st_size if self.source.exists() else 0
        if size < self.state.offset:
            self._halt("source_truncated", file_size=size, expected_min_size=self.state.offset)
        with self.source.open("rb") as f:
            start = max(0, self.state.offset - 65536)
            f.seek(start)
            chunk = f.read(self.state.offset - start)
        last_line = chunk.rstrip(b"\n").rsplit(b"\n", 1)[-1]
        try:
            rec = json.loads(last_line)
        except ValueError:
            self._halt("source_diverged", detail="checkpoint does not land on a record boundary")
        if rec.get("seq") != self.state.last_seq or rec.get("hash") != self.state.last_hash:
            self._halt("source_diverged", found_seq=rec.get("seq"), found_hash=rec.get("hash"))

    def read_batch(self) -> list[bytes]:
        if not self.source.exists():
            return []
        lines: list[bytes] = []
        with self.source.open("rb") as f:
            f.seek(self.state.offset)
            while len(lines) < self.s.audit_ship_batch_max_records:
                line = f.readline()
                if not line.endswith(b"\n"):   # EOF or a line still being written
                    break
                if line.strip():
                    lines.append(line)
            SOURCE_SEQ.set(self._peek_last_seq())
        return lines

    def _peek_last_seq(self) -> int:
        with self.source.open("rb") as f:
            f.seek(0, os.SEEK_END)
            end = f.tell()
            f.seek(max(0, end - 65536))
            tail = f.read().rstrip(b"\n").rsplit(b"\n", 1)[-1]
        try:
            return int(json.loads(tail)["seq"]) if tail else 0
        except (ValueError, KeyError):
            return self.state.last_seq

    def validate_chain(self, lines: list[bytes]) -> list[dict]:
        prev, seq = self.state.last_hash, self.state.last_seq
        records = []
        for raw in lines:
            rec = json.loads(raw)
            if rec.get("seq") != seq + 1 or not link_ok(prev, rec):
                self._halt("chain_break", at_seq=rec.get("seq"), expected_seq=seq + 1)
            prev, seq = rec["hash"], rec["seq"]
            records.append(rec)
        return records

    def should_flush(self, records: list[dict]) -> bool:
        if len(records) >= self.s.audit_ship_batch_max_records:
            return True
        oldest = datetime.fromisoformat(records[0]["ts"])
        return (datetime.now(timezone.utc) - oldest).total_seconds() >= self.s.audit_ship_flush_seconds

    # ---------- upload ----------
    def segment_key(self, records: list[dict]) -> str:
        day = datetime.fromisoformat(records[0]["ts"]).strftime("%Y/%m/%d")
        return f"{self.s.audit_s3_prefix.strip('/')}/{day}/{records[0]['seq']:012d}-{records[-1]['seq']:012d}.jsonl"

    def upload(self, lines: list[bytes], records: list[dict]) -> dict[str, Any]:
        body = b"".join(lines)
        sha256 = hashlib.sha256(body).hexdigest()
        key = self.segment_key(records)
        bucket = self.s.audit_s3_bucket

        try:
            head = self.s3.head_object(Bucket=bucket, Key=key)
            existing = head.get("Metadata", {}).get("sha256")
            if existing != sha256:
                self._halt("segment_conflict", key=key, existing_sha256=existing, local_sha256=sha256)
            return {"key": key, "version_id": head.get("VersionId"), "sha256": sha256, "reused": True}
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") not in ("404", "NoSuchKey", "NotFound"):
                raise

        retain_until = datetime.now(timezone.utc) + timedelta(days=self.s.audit_s3_retention_days)
        params: dict[str, Any] = dict(
            Bucket=bucket, Key=key, Body=body, ContentType="application/x-ndjson",
            ContentMD5=base64.b64encode(hashlib.md5(body).digest()).decode(),
            ChecksumAlgorithm="SHA256",
            ObjectLockMode=self.s.audit_s3_lock_mode, ObjectLockRetainUntilDate=retain_until,
            Metadata={"first-seq": str(records[0]["seq"]), "last-seq": str(records[-1]["seq"]),
                      "first-prev-hash": records[0]["prev_hash"], "last-hash": records[-1]["hash"],
                      "sha256": sha256, "source-host": socket.gethostname()},
        )
        if self.s.audit_s3_kms_key_id:
            params.update(ServerSideEncryption="aws:kms", SSEKMSKeyId=self.s.audit_s3_kms_key_id)
        resp = self.s3.put_object(**params)
        return {"key": key, "version_id": resp.get("VersionId"), "sha256": sha256,
                "retain_until": retain_until.isoformat(), "reused": False}

    def ship_once(self) -> int:
        """Ship at most one segment. Returns number of records archived (0 if nothing due)."""
        lines = self.read_batch()
        LAG.set(max(0, self._peek_last_seq() - self.state.last_seq) if self.source.exists() else 0)
        if not lines:
            return 0
        records = self.validate_chain(lines)
        if not self.should_flush(records):
            return 0
        try:
            result = self.upload(lines, records)
        except (ClientError, BotoCoreError) as exc:
            SEGMENTS.labels("failure").inc()
            log.error("segment upload failed: %r", exc)
            audit_event("audit.segment.ship_failed", first_seq=records[0]["seq"],
                        last_seq=records[-1]["seq"], error=repr(exc))
            return 0

        self.state = ShipState(offset=self.state.offset + sum(len(x) for x in lines),
                               last_seq=records[-1]["seq"], last_hash=records[-1]["hash"])
        self._save_state()
        SEGMENTS.labels("reused" if result["reused"] else "success").inc()
        SHIPPED_RECORDS.inc(len(records))
        SHIPPED_SEQ.set(self.state.last_seq)
        LAST_SUCCESS.set(time.time())
        LAG.set(max(0, self._peek_last_seq() - self.state.last_seq))
        audit_event("audit.segment.shipped", bucket=self.s.audit_s3_bucket, records=len(records),
                    first_seq=records[0]["seq"], last_seq=records[-1]["seq"],
                    last_hash=records[-1]["hash"], lock_mode=self.s.audit_s3_lock_mode, **result)
        return len(records)

    def run_forever(self) -> None:
        audit_event("audit.shipper.started", bucket=self.s.audit_s3_bucket, prefix=self.s.audit_s3_prefix,
                    lock_mode=self.s.audit_s3_lock_mode, retention_days=self.s.audit_s3_retention_days,
                    resume_from_seq=self.state.last_seq)
        last_check = 0.0
        while True:
            try:
                if self.halt_reason is None:
                    if time.monotonic() - last_check > 60:
                        self.check_source_matches_shipped()
                        last_check = time.monotonic()
                    while self.ship_once():   # drain backlog quickly
                        pass
            except HaltShipping:
                pass  # stay up so metrics/alerts show the halt; needs human investigation
            except Exception:
                log.exception("shipper loop error")
            time.sleep(self.s.audit_ship_poll_seconds)


# ---------- verification ----------
_LINK_FIELDS = ("intent_seq", "received_seq", "failed_seq")


def _slim(rec: dict[str, Any]) -> dict[str, Any]:
    """Everything the checks need after the record's own hash has been verified once."""
    details = rec.get("details") or {}
    return {"seq": rec["seq"], "hash": rec.get("hash"), "prev_hash": rec.get("prev_hash"),
            "self_ok": link_ok(rec.get("prev_hash"), rec), "action": rec.get("action", ""),
            "ts": rec.get("ts"), "resource": rec.get("resource"),
            "details": {k: details[k] for k in _LINK_FIELDS if k in details}}


def _load_version(s3, bucket: str, key: str, version_id: str) -> dict[str, Any]:
    got = s3.get_object(Bucket=bucket, Key=key, VersionId=version_id)
    body = got["Body"].read()
    lines = [body] if "/journal/" in key else [x for x in body.splitlines() if x.strip()]
    return {"key": key, "journal": "/journal/" in key,
            "sha_ok": got.get("Metadata", {}).get("sha256") == hashlib.sha256(body).hexdigest(),
            # GetObject returns the lock headers when the caller has s3:GetObjectRetention.
            "lock_mode": got.get("ObjectLockMode"), "until": got.get("ObjectLockRetainUntilDate"),
            "records": [_slim(json.loads(x)) for x in lines]}


def verify_archive(settings: ShipperSettings, s3=None, compare_local: str | None = None,
                   cache: dict[str, dict] | None = None) -> dict[str, Any]:
    """Full logical check of the archive.

    `cache` (version_id -> parsed object) makes repeated runs incremental: Object Lock versions are
    immutable, so a version already downloaded and hash-checked never needs fetching again. Only the
    listing is repeated, which also surfaces new versions and delete markers.
    """
    s3 = s3 or make_s3(settings)
    cache = cache if cache is not None else {}
    bucket, prefix = settings.audit_s3_bucket, settings.audit_s3_prefix.strip("/") + "/"
    by_seq: dict[int, dict] = {}
    journal: dict[int, dict] = {}
    report: dict[str, Any] = {"bucket": bucket, "prefix": prefix, "objects": 0, "fetched": 0, "conflicts": [],
                              "unlocked_objects": [], "checksum_mismatches": [], "delete_markers": [],
                              "journal_conflicts": [], "journal_invalid": [], "warnings": []}
    now = datetime.now(timezone.utc)
    live_versions: set[str] = set()

    # Walk every version, not just current objects: a plain DELETE on a locked bucket is allowed but only
    # adds a delete marker that hides the (still locked) version. Read through it and report the marker.
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket, Prefix=prefix):
        for marker in page.get("DeleteMarkers", []):
            report["delete_markers"].append({"key": marker["Key"], "version_id": marker.get("VersionId"),
                                             "at": marker.get("LastModified")})
        for obj in page.get("Versions", []):
            key, vid = obj["Key"], obj["VersionId"]
            live_versions.add(vid)
            report["objects"] += 1
            entry = cache.get(vid)
            if entry is None:
                entry = cache[vid] = _load_version(s3, bucket, key, vid)
                report["fetched"] += 1
            if not entry["sha_ok"]:
                report["checksum_mismatches"].append(key)
            if not entry["lock_mode"] or entry["until"] is None:
                report["unlocked_objects"].append({"key": key, "reason": "no retention"})
            elif entry["until"] <= now:
                report["unlocked_objects"].append({"key": key, "reason": "retention expired"})
            if entry["journal"]:
                rec = entry["records"][0]
                if not rec["self_ok"]:
                    report["journal_invalid"].append(key)
                elif rec["seq"] in journal and journal[rec["seq"]]["hash"] != rec["hash"]:
                    report["journal_conflicts"].append({"seq": rec["seq"], "key": key})
                journal.setdefault(rec["seq"], rec)
                continue
            for rec in entry["records"]:
                if rec["seq"] in by_seq and by_seq[rec["seq"]]["hash"] != rec["hash"]:
                    report["conflicts"].append({"seq": rec["seq"], "key": key})
                by_seq.setdefault(rec["seq"], rec)
    for vid in set(cache) - live_versions:   # versions that vanished from the listing
        report["warnings"].append(f"previously verified version disappeared: {cache[vid]['key']} ({vid})")

    prev, gaps, first_bad = GENESIS_HASH, [], None
    head = max(by_seq, default=0)
    for seq in range(1, head + 1):
        rec = by_seq.get(seq)
        if rec is None:
            gaps.append(seq)
            first_bad = first_bad or seq
            break
        if not rec["self_ok"] or rec["prev_hash"] != prev:
            first_bad = first_bad or seq
            break
        prev = rec["hash"]
    report.update(records=len(by_seq), head_seq=head, head_hash=by_seq[head]["hash"] if head else None,
                  gaps=gaps, first_bad_seq=first_bad)

    # --- journal vs segments ---
    report["journal_records"] = len(journal)
    report["journal_mismatches"] = [q for q, r in journal.items() if q in by_seq and by_seq[q]["hash"] != r["hash"]]
    report["journal_only"] = sum(1 for q in journal if q not in by_seq)   # not yet segmented: normal
    combined = {**journal, **by_seq}
    if journal:
        # Once journaling started, every archived record must also be in the journal, unless it is a
        # local-only `audit.journal.write_failed` marker or the record that marker explains. Anything else
        # was written to the file without going through the gateway (e.g. injected on the host).
        first_journaled = min(journal)
        explained = {r["details"].get("failed_seq") for r in combined.values()
                     if r["action"] == "audit.journal.write_failed"}
        report["not_journaled"] = sorted(
            q for q, r in by_seq.items()
            if q > first_journaled and q not in journal and q not in explained
            and r["action"] != "audit.journal.write_failed")[:50]
    else:
        report["not_journaled"] = []

    # --- write-ahead intents without an outcome (crash between action and outcome, or in flight) ---
    done = {r["details"].get(k) for r in combined.values() for k in ("intent_seq", "received_seq")}
    failed = {r["details"].get("failed_seq") for r in combined.values()
              if r["action"] == "audit.journal.write_failed"}
    cutoff = now - timedelta(minutes=5)
    open_intents = [{"seq": q, "action": r["action"], "resource": r.get("resource"), "ts": r["ts"]}
                    for q, r in sorted(combined.items())
                    if (r["action"].endswith(".intent") or r["action"] == "http.request.received")
                    and q not in done and q not in failed and datetime.fromisoformat(r["ts"]) < cutoff]
    report["open_intents"] = open_intents[:50]
    report["open_intent_count"] = len(open_intents)
    if open_intents:
        report["warnings"].append(f"{len(open_intents)} durable intents have no recorded outcome")

    if compare_local:
        mismatches, local_head = [], 0
        archived_head = max(head, max(journal, default=0))
        with open(compare_local, encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                rec = json.loads(line)
                local_head = rec["seq"]
                archived = by_seq.get(rec["seq"]) or journal.get(rec["seq"])
                if archived is not None and archived["hash"] != rec["hash"]:
                    mismatches.append(rec["seq"])
        report["local"] = {"head_seq": local_head, "unshipped": max(0, local_head - archived_head),
                           "mismatched_seqs": mismatches[:20], "mismatch_count": len(mismatches),
                           "missing_locally": max(0, archived_head - local_head)}

    report["findings"] = {
        "conflicts": len(report["conflicts"]), "unlocked_objects": len(report["unlocked_objects"]),
        "checksum_mismatches": len(report["checksum_mismatches"]), "delete_markers": len(report["delete_markers"]),
        "chain_break": int(bool(first_bad)), "journal_conflicts": len(report["journal_conflicts"]),
        "journal_invalid": len(report["journal_invalid"]), "journal_mismatches": len(report["journal_mismatches"]),
        "not_journaled": len(report["not_journaled"]),
        "local_mismatches": report["local"]["mismatch_count"] if compare_local else 0,
        "missing_locally": report["local"]["missing_locally"] if compare_local else 0,
    }
    report["ok"] = not any(report["findings"].values())
    return report


VERIFY_OK = Gauge("audit_archive_verify_ok", "1 if the last scheduled archive verification passed")
VERIFY_LAST_RUN = Gauge("audit_archive_verify_last_run_timestamp_seconds", "Last completed verification")
VERIFY_DURATION = Gauge("audit_archive_verify_duration_seconds", "Duration of the last verification")
VERIFY_FINDINGS = Gauge("audit_archive_verify_findings", "Findings from the last verification", ["check"])
VERIFY_OPEN_INTENTS = Gauge("audit_archive_open_intents", "Durable intents >5 min old with no outcome")
VERIFY_FETCHED = Counter("audit_archive_verify_objects_fetched_total", "Object versions downloaded by the verifier")
VERIFY_ERRORS = Counter("audit_archive_verify_errors_total", "Verification runs that errored")


class ScheduledVerifier:
    """Runs verify_archive every N seconds in the sidecar and exports the result as metrics."""

    def __init__(self, settings: ShipperSettings, s3=None):
        self.s = settings
        self.s3 = s3 or make_s3(settings)
        self.cache: dict[str, dict] = {}
        self.last_report: dict[str, Any] | None = None

    def run_once(self) -> dict[str, Any]:
        start = time.monotonic()
        compare = self.s.audit_log_path if Path(self.s.audit_log_path).exists() else None
        report = verify_archive(self.s, s3=self.s3, compare_local=compare, cache=self.cache)
        VERIFY_DURATION.set(time.monotonic() - start)
        VERIFY_LAST_RUN.set(time.time())
        VERIFY_OK.set(1 if report["ok"] else 0)
        VERIFY_FETCHED.inc(report["fetched"])
        VERIFY_OPEN_INTENTS.set(report["open_intent_count"])
        for check, n in report["findings"].items():
            VERIFY_FINDINGS.labels(check).set(n)
        audit_event("audit.archive.verified", ok=report["ok"], head_seq=report["head_seq"],
                    objects=report["objects"], fetched=report["fetched"],
                    findings={k: v for k, v in report["findings"].items() if v},
                    open_intents=report["open_intent_count"])
        self.last_report = report
        return report

    def run_forever(self) -> None:
        time.sleep(min(60, self.s.audit_verify_interval_seconds))   # let the stack settle first
        while True:
            try:
                self.run_once()
            except Exception:
                VERIFY_ERRORS.inc()
                log.exception("scheduled verification failed")
            time.sleep(self.s.audit_verify_interval_seconds)


# ---------- synchronous journal gateway ----------
def journal_key(settings: ShipperSettings, seq: int) -> str:
    return f"{settings.audit_s3_prefix.strip('/')}/journal/{seq:012d}.json"


def create_gateway(settings: ShipperSettings, s3=None, shipper: "Shipper | None" = None,
                   verifier: "ScheduledVerifier | None" = None) -> FastAPI:
    s3 = s3 or make_s3(settings)
    retention_days = settings.audit_s3_journal_retention_days or settings.audit_s3_retention_days
    app = FastAPI(title="Audit gateway", docs_url=None, redoc_url=None)
    app.mount("/metrics", make_asgi_app())

    def reject(status: int, reason: str, **details: Any):
        JOURNAL_WRITES.labels(reason).inc()
        audit_event("audit.journal.rejected", reason=reason, **details)
        raise HTTPException(status_code=status, detail=reason)

    s3_state = {"last_ok": 0.0, "last_error": 0.0}
    # boto's own timeouts don't bound a PutObject against a hung peer (100-continue, retries), so each
    # put runs under a hard deadline. A put that lands after we gave up is harmless: the app has already
    # refused the action and logged `audit.journal.write_failed` for that seq, which the verifier accepts.
    put_pool = ThreadPoolExecutor(max_workers=32, thread_name_prefix="journal-put")

    @app.get("/health")
    def health():
        """Liveness only."""
        return {"status": "ok", "shipper_halted": bool(shipper and shipper.halt_reason)}

    @app.get("/verify/last")
    def last_verification():
        """Most recent scheduled verification report."""
        if verifier is None or verifier.last_report is None:
            raise HTTPException(status_code=404, detail="no verification has run yet")
        return JSONResponse(content=json.loads(json.dumps(verifier.last_report, default=str)))

    @app.get("/ready")
    def ready():
        """Not ready while the most recent S3 write failed (within 30s): the app then reports not-ready
        instead of discovering the outage one refused request at a time."""
        degraded = s3_state["last_error"] > s3_state["last_ok"] and time.time() - s3_state["last_error"] < 30
        return JSONResponse(status_code=503 if degraded else 200,
                            content={"ready": not degraded, "last_s3_ok": s3_state["last_ok"],
                                     "last_s3_error": s3_state["last_error"]})

    # Sync def: FastAPI runs it in a threadpool, so blocking boto3 calls don't stall other writes.
    @app.post("/v1/journal", status_code=201)
    def put_journal(record: dict = Body(...), authorization: str = Header("")):
        accepted = [t for t in (settings.audit_journal_token, settings.audit_journal_token_previous) if t]
        # Compare against every accepted token (no short-circuit) to keep timing uniform.
        matches = [hmac.compare_digest(authorization, f"Bearer {t}") for t in accepted]
        if not any(matches):
            reject(401, "unauthorized")
        seq = record.get("seq")
        if not isinstance(seq, int) or seq < 1 or not isinstance(record.get("action"), str):
            reject(400, "malformed", seq=seq)
        if not link_ok(record.get("prev_hash"), record):
            reject(400, "hash_invalid", seq=seq)

        body = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
        sha256 = hashlib.sha256(body).hexdigest()
        key = journal_key(settings, seq)
        params: dict[str, Any] = dict(
            Bucket=settings.audit_s3_bucket, Key=key, Body=body, ContentType="application/json",
            IfNoneMatch="*",   # never overwrite an existing seq
            ContentMD5=base64.b64encode(hashlib.md5(body).digest()).decode(), ChecksumAlgorithm="SHA256",
            ObjectLockMode=settings.audit_s3_lock_mode,
            ObjectLockRetainUntilDate=datetime.now(timezone.utc) + timedelta(days=retention_days),
            Metadata={"seq": str(seq), "hash": record["hash"], "sha256": sha256},
        )
        if settings.audit_s3_kms_key_id:
            params.update(ServerSideEncryption="aws:kms", SSEKMSKeyId=settings.audit_s3_kms_key_id)
        start = time.perf_counter()
        try:
            resp = put_pool.submit(s3.put_object, **params).result(
                timeout=settings.audit_journal_put_timeout_seconds)
        except FutureTimeout:
            JOURNAL_WRITES.labels("s3_timeout").inc()
            s3_state["last_error"] = time.time()
            log.error("journal put exceeded %.1fs deadline (seq %s)", settings.audit_journal_put_timeout_seconds, seq)
            raise HTTPException(status_code=503, detail="s3 timeout")
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code in ("PreconditionFailed", "412", "ConditionalRequestConflict"):
                existing = s3.head_object(Bucket=settings.audit_s3_bucket, Key=key)
                if existing.get("Metadata", {}).get("sha256") == sha256:
                    JOURNAL_WRITES.labels("duplicate").inc()   # retry of a write that already landed
                    return JSONResponse(status_code=200, content={"key": key, "version_id": existing.get("VersionId"),
                                                                  "duplicate": True})
                reject(409, "seq_conflict", seq=seq, key=key)
            JOURNAL_WRITES.labels("s3_error").inc()
            s3_state["last_error"] = time.time()
            log.error("journal put failed: %r", e)
            raise HTTPException(status_code=503, detail=f"s3 error: {code}")
        except BotoCoreError as e:
            JOURNAL_WRITES.labels("s3_error").inc()
            s3_state["last_error"] = time.time()
            log.error("journal put failed: %r", e)
            raise HTTPException(status_code=503, detail="s3 unreachable")
        finally:
            JOURNAL_S3_LATENCY.observe(time.perf_counter() - start)
        JOURNAL_WRITES.labels("success").inc()
        s3_state["last_ok"] = time.time()
        return {"key": key, "version_id": resp.get("VersionId"), "sha256": sha256}

    return app


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format='{"level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}')
    p = argparse.ArgumentParser(prog="audit_shipper")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("run")
    v = sub.add_parser("verify")
    v.add_argument("--compare-local", help="also check a local audit.jsonl against the archive")
    args = p.parse_args(argv)
    settings = ShipperSettings()
    if not settings.audit_s3_bucket:
        print("AUDIT_S3_BUCKET is required", file=sys.stderr)
        return 2
    if settings.secrets_manager_secret_id:
        from app.secrets import SHIPPER_SECRET_FIELDS, SecretsError, SecretsLoader
        loader = SecretsLoader(settings, settings.secrets_manager_secret_id, SHIPPER_SECRET_FIELDS,
                               region=settings.secrets_manager_region,
                               endpoint_url=settings.secrets_manager_endpoint_url,
                               # stdout carries the JSON report in `verify` mode, so audit lines go to stderr there
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
        shipper = Shipper(settings, s3=s3)
        threading.Thread(target=shipper.run_forever, name="segment-shipper", daemon=True).start()
        verifier = None
        if settings.audit_verify_interval_seconds > 0:
            verifier = ScheduledVerifier(settings, s3=s3)
            threading.Thread(target=verifier.run_forever, name="archive-verifier", daemon=True).start()
        uvicorn.run(create_gateway(settings, s3=s3, shipper=shipper, verifier=verifier), host="0.0.0.0",
                    port=settings.audit_ship_metrics_port, log_level="warning")
        return 0
    report = verify_archive(settings, compare_local=args.compare_local)
    audit_event("audit.archive.verified", stream=sys.stderr, ok=report["ok"], head_seq=report["head_seq"],
                objects=report["objects"], delete_markers=len(report["delete_markers"]))
    print(json.dumps(report, indent=2, default=str))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
