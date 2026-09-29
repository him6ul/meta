import json
from datetime import datetime, timezone

import boto3
import pytest
from moto import mock_aws

from app.audit import AuditLog
from app.audit_shipper import HaltShipping, Shipper, ShipperSettings, verify_archive

BUCKET = "audit-test"


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    with mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket=BUCKET, ObjectLockEnabledForBucket=True)
        settings = ShipperSettings(
            audit_log_path=str(tmp_path / "audit.jsonl"),
            audit_shipper_state_path=str(tmp_path / "state.json"),
            audit_s3_bucket=BUCKET, audit_s3_retention_days=1,
            audit_ship_batch_max_records=3, audit_ship_flush_seconds=0,
        )
        yield settings, s3, AuditLog(settings.audit_log_path)


def drain(shipper):
    while shipper.ship_once():
        pass


def test_ships_locked_segments_and_verifies(env):
    settings, s3, log = env
    for i in range(7):
        log.record("test.action", n=i)
    shipper = Shipper(settings, s3=s3)
    drain(shipper)

    keys = [o["Key"] for o in s3.list_objects_v2(Bucket=BUCKET)["Contents"]]
    assert len(keys) == 3 and keys[0].endswith("000000000001-000000000003.jsonl")
    head = s3.head_object(Bucket=BUCKET, Key=keys[0])
    assert head["ObjectLockMode"] == "GOVERNANCE"
    assert head["ObjectLockRetainUntilDate"] > datetime.now(timezone.utc)
    meta = s3.head_object(Bucket=BUCKET, Key=keys[-1])["Metadata"]
    assert meta["last-seq"] == "7" and meta["last-hash"] == log._prev_hash

    report = verify_archive(settings, s3=s3, compare_local=settings.audit_log_path)
    assert report["ok"] and report["head_seq"] == 7 and report["local"]["unshipped"] == 0


def test_resumes_from_checkpoint_without_duplicates(env):
    settings, s3, log = env
    for i in range(3):
        log.record("a", n=i)
    drain(Shipper(settings, s3=s3))
    for i in range(3):
        log.record("b", n=i)
    restarted = Shipper(settings, s3=s3)
    restarted.check_source_matches_shipped()
    drain(restarted)
    keys = [o["Key"] for o in s3.list_objects_v2(Bucket=BUCKET)["Contents"]]
    assert [k.rsplit("/", 1)[1] for k in keys] == ["000000000001-000000000003.jsonl",
                                                    "000000000004-000000000006.jsonl"]


def test_waits_for_flush_interval(env):
    settings, s3, log = env
    settings.audit_ship_flush_seconds = 3600
    log.record("only.one")
    assert Shipper(settings, s3=s3).ship_once() == 0
    assert "Contents" not in s3.list_objects_v2(Bucket=BUCKET)


def test_halts_on_tampered_unshipped_record(env):
    settings, s3, log = env
    for i in range(3):
        log.record("x", n=i)
    lines = open(settings.audit_log_path).read().splitlines()
    rec = json.loads(lines[1]); rec["actor"] = "forged"; lines[1] = json.dumps(rec)
    open(settings.audit_log_path, "w").write("\n".join(lines) + "\n")
    shipper = Shipper(settings, s3=s3)
    with pytest.raises(HaltShipping):
        shipper.ship_once()
    assert shipper.halt_reason == "chain_break"
    assert "Contents" not in s3.list_objects_v2(Bucket=BUCKET)  # nothing forged got archived


def test_halts_when_local_log_diverges_from_archive(env):
    settings, s3, log = env
    for i in range(3):
        log.record("x", n=i)
    drain(Shipper(settings, s3=s3))
    # Someone replaces the whole local file with a freshly generated, internally valid chain.
    open(settings.audit_log_path, "w").close()
    fake = AuditLog(settings.audit_log_path)
    for i in range(3):
        fake.record("rewritten", n=i)
    shipper = Shipper(settings, s3=s3)
    with pytest.raises(HaltShipping):
        shipper.check_source_matches_shipped()
    assert shipper.halt_reason == "source_diverged"
    report = verify_archive(settings, s3=s3, compare_local=settings.audit_log_path)
    assert not report["ok"] and report["local"]["mismatch_count"] == 3


def test_halts_when_local_log_truncated(env):
    settings, s3, log = env
    for i in range(3):
        log.record("x", n=i)
    drain(Shipper(settings, s3=s3))
    open(settings.audit_log_path, "w").close()
    shipper = Shipper(settings, s3=s3)
    with pytest.raises(HaltShipping):
        shipper.check_source_matches_shipped()
    assert shipper.halt_reason == "source_truncated"


def test_verify_detects_gap_and_unlocked_object(env):
    settings, s3, log = env
    for i in range(6):
        log.record("x", n=i)
    drain(Shipper(settings, s3=s3))
    first = s3.list_objects_v2(Bucket=BUCKET)["Contents"][0]["Key"]
    # An object written without retention (e.g. by someone bypassing the shipper) must be flagged.
    s3.put_object(Bucket=BUCKET, Key=settings.audit_s3_prefix + "/stray.jsonl", Body=b"")
    # Governance mode lets a privileged caller delete; the verifier must notice the hole.
    s3.delete_object(Bucket=BUCKET, Key=first, BypassGovernanceRetention=True,
                     VersionId=s3.head_object(Bucket=BUCKET, Key=first)["VersionId"])
    report = verify_archive(settings, s3=s3)
    assert not report["ok"]
    assert report["gaps"] == [1]
    assert any(o["reason"] == "no retention" for o in report["unlocked_objects"])


def test_verify_reads_through_delete_markers_and_flags_them(env):
    settings, s3, log = env
    for i in range(3):
        log.record("x", n=i)
    drain(Shipper(settings, s3=s3))
    key = s3.list_objects_v2(Bucket=BUCKET)["Contents"][0]["Key"]
    s3.delete_object(Bucket=BUCKET, Key=key)  # allowed on a locked bucket: adds a delete marker only
    assert "Contents" not in s3.list_objects_v2(Bucket=BUCKET)

    report = verify_archive(settings, s3=s3)
    assert report["head_seq"] == 3 and report["gaps"] == []   # locked version still read and verified
    assert [m["key"] for m in report["delete_markers"]] == [key]
    assert report["ok"] is False                                # but the attempt is reported
