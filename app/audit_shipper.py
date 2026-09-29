"""Ship the hash-chained audit log to S3 with Object Lock (WORM), and verify what was shipped.

Runs as a sidecar with its own S3 credentials and a read-only view of the audit log, so the app
never holds credentials that could alter the archive.

  python -m app.audit_shipper run                         # tail + ship forever
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

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from prometheus_client import Counter, Gauge, start_http_server
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
    audit_s3_kms_key_id: str = ""            # SSE-KMS key; empty = bucket default encryption
    audit_ship_batch_max_records: int = 500
    audit_ship_flush_seconds: float = 10.0
    audit_ship_poll_seconds: float = 1.0
    audit_ship_metrics_port: int = 9102


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
    cfg = Config(retries={"mode": "standard", "max_attempts": 5},
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
def verify_archive(settings: ShipperSettings, s3=None, compare_local: str | None = None) -> dict[str, Any]:
    s3 = s3 or make_s3(settings)
    bucket, prefix = settings.audit_s3_bucket, settings.audit_s3_prefix.strip("/") + "/"
    by_seq: dict[int, dict] = {}
    report: dict[str, Any] = {"bucket": bucket, "prefix": prefix, "objects": 0, "conflicts": [],
                              "unlocked_objects": [], "checksum_mismatches": [], "delete_markers": []}

    # Walk every version, not just current objects: a plain DELETE on a locked bucket is allowed but only
    # adds a delete marker that hides the (still locked) version. Read through it and report the marker.
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket, Prefix=prefix):
        for marker in page.get("DeleteMarkers", []):
            report["delete_markers"].append({"key": marker["Key"], "version_id": marker.get("VersionId"),
                                             "at": marker.get("LastModified")})
        for obj in page.get("Versions", []):
            key = obj["Key"]
            report["objects"] += 1
            got = s3.get_object(Bucket=bucket, Key=key, VersionId=obj["VersionId"])
            body = got["Body"].read()
            if got.get("Metadata", {}).get("sha256") != hashlib.sha256(body).hexdigest():
                report["checksum_mismatches"].append(key)
            # GetObject returns the lock headers when the caller has s3:GetObjectRetention.
            until = got.get("ObjectLockRetainUntilDate")
            if not got.get("ObjectLockMode") or until is None:
                report["unlocked_objects"].append({"key": key, "reason": "no retention"})
            elif until <= datetime.now(timezone.utc):
                report["unlocked_objects"].append({"key": key, "reason": "retention expired"})
            for line in body.splitlines():
                if not line.strip():
                    continue
                rec = json.loads(line)
                if rec["seq"] in by_seq and by_seq[rec["seq"]]["hash"] != rec["hash"]:
                    report["conflicts"].append({"seq": rec["seq"], "key": key})
                by_seq.setdefault(rec["seq"], rec)

    prev, gaps, first_bad = GENESIS_HASH, [], None
    head = max(by_seq, default=0)
    for seq in range(1, head + 1):
        rec = by_seq.get(seq)
        if rec is None:
            gaps.append(seq)
            first_bad = first_bad or seq
            break
        if not link_ok(prev, rec):
            first_bad = first_bad or seq
            break
        prev = rec["hash"]
    report.update(records=len(by_seq), head_seq=head, head_hash=by_seq[head]["hash"] if head else None,
                  gaps=gaps, first_bad_seq=first_bad)

    if compare_local:
        mismatches, local_head = [], 0
        with open(compare_local, encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                rec = json.loads(line)
                local_head = rec["seq"]
                archived = by_seq.get(rec["seq"])
                if archived is not None and archived["hash"] != rec["hash"]:
                    mismatches.append(rec["seq"])
        report["local"] = {"head_seq": local_head, "unshipped": max(0, local_head - head),
                           "mismatched_seqs": mismatches[:20], "mismatch_count": len(mismatches),
                           "missing_locally": max(0, head - local_head)}

    report["ok"] = not (report["conflicts"] or report["unlocked_objects"] or report["checksum_mismatches"]
                        or report["delete_markers"] or first_bad or (compare_local and (report["local"]["mismatch_count"]
                                                            or report["local"]["missing_locally"])))
    return report


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
    if args.cmd == "run":
        start_http_server(settings.audit_ship_metrics_port)
        Shipper(settings).run_forever()
        return 0
    report = verify_archive(settings, compare_local=args.compare_local)
    audit_event("audit.archive.verified", stream=sys.stderr, ok=report["ok"], head_seq=report["head_seq"],
                objects=report["objects"], delete_markers=len(report["delete_markers"]))
    print(json.dumps(report, indent=2, default=str))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
