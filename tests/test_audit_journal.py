"""Synchronous journal: write-ahead intents, fail-closed behaviour, gateway guarantees, verifier checks."""
import json

import boto3
import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from moto import mock_aws

from app.audit import AuditLog
from app.audit_shipper import Shipper, ShipperSettings, create_gateway, verify_archive
from app.config import get_settings
from app.main import create_app

BUCKET = "journal-test"
TOKEN = "journal-token"
GRAPH = "https://graph.test/v24.0"


@pytest.fixture
def s3(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket=BUCKET, ObjectLockEnabledForBucket=True)
        yield client


@pytest.fixture
def shipper_settings(tmp_path, fresh_audit_log):
    return ShipperSettings(audit_log_path=str(fresh_audit_log), audit_shipper_state_path=str(tmp_path / "st.json"),
                           audit_s3_bucket=BUCKET, audit_s3_retention_days=1, audit_journal_token=TOKEN,
                           audit_ship_flush_seconds=0)


@pytest.fixture
def gateway(s3, shipper_settings):
    return create_gateway(shipper_settings, s3=s3)


@pytest.fixture
def journaled_env(monkeypatch):
    monkeypatch.setenv("AUDIT_JOURNAL_URL", "http://gateway")
    monkeypatch.setenv("AUDIT_JOURNAL_TOKEN", TOKEN)
    get_settings.cache_clear()


def journal_records(s3):
    keys = [o["Key"] for o in s3.list_objects_v2(Bucket=BUCKET).get("Contents", []) if "/journal/" in o["Key"]]
    return [json.loads(s3.get_object(Bucket=BUCKET, Key=k)["Body"].read()) for k in keys]


def make_record(log_path, action="test.action"):
    return AuditLog(str(log_path)).record(action)


# ---------- gateway ----------
def test_gateway_writes_locked_record_and_refuses_overwrite(gateway, s3, tmp_path):
    rec = make_record(tmp_path / "g.jsonl")
    c = TestClient(gateway)
    auth = {"authorization": f"Bearer {TOKEN}"}
    r = c.post("/v1/journal", json=rec, headers=auth)
    assert r.status_code == 201
    head = s3.head_object(Bucket=BUCKET, Key=r.json()["key"])
    assert head["ObjectLockMode"] == "GOVERNANCE"

    assert c.post("/v1/journal", json=rec, headers=auth).json()["duplicate"] is True  # idempotent retry

    forged = AuditLog(str(tmp_path / "other.jsonl")).record("forged.action")  # same seq 1, other content
    assert forged["seq"] == rec["seq"]
    assert c.post("/v1/journal", json=forged, headers=auth).status_code == 409


def test_gateway_rejects_bad_token_and_bad_hash(gateway, tmp_path):
    rec = make_record(tmp_path / "g.jsonl")
    c = TestClient(gateway)
    assert c.post("/v1/journal", json=rec).status_code == 401
    assert c.post("/v1/journal", json=rec, headers={"authorization": "Bearer nope"}).status_code == 401
    tampered = {**rec, "actor": "someone-else"}
    assert c.post("/v1/journal", json=tampered, headers={"authorization": f"Bearer {TOKEN}"}).status_code == 400


# ---------- app + gateway end to end ----------
@respx.mock
def test_every_step_is_durable_before_the_next(gateway, s3, journaled_env, shipper_settings):
    respx.post(f"{GRAPH}/1098765/messages").respond(200, json={"messages": [{"id": "wamid.1"}]})
    with TestClient(create_app(journal_transport=httpx.ASGITransport(app=gateway))) as c:
        r = c.post("/api/whatsapp/messages", json={"to": "15551234567", "text": "hi"})
    assert r.status_code == 200 and "x-audit-outcome" not in r.headers

    by_action = {x["action"]: x for x in journal_records(s3)}
    received, intent = by_action["http.request.received"], by_action["meta.api.post.intent"]
    outcome, done = by_action["meta.api.post"], by_action["http.request"]
    assert received["seq"] < intent["seq"] < outcome["seq"] < done["seq"]
    assert outcome["details"]["intent_seq"] == intent["seq"]
    assert done["details"]["received_seq"] == received["seq"]
    assert outcome["details"]["result_object_ids"] == ["wamid.1"]

    report = verify_archive(shipper_settings, s3=s3)
    assert report["ok"] and report["journal_records"] >= 5 and report["journal_only"] >= 5


class FlakyJournal(httpx.AsyncBaseTransport):
    """Accepts records until `fail` is set (optionally only for some actions)."""

    def __init__(self, gateway):
        self.inner = httpx.ASGITransport(app=gateway)
        self.fail_actions: set[str] | None = None

    async def handle_async_request(self, request):
        if request.url.path == "/v1/journal" and self.fail_actions is not None:
            action = json.loads(request.content)["action"]
            if not self.fail_actions or action in self.fail_actions:
                return httpx.Response(503, text="s3 down")
        return await self.inner.handle_async_request(request)


@respx.mock
def test_fail_closed_meta_never_called_when_journal_down(gateway, journaled_env, fresh_audit_log):
    meta = respx.post(f"{GRAPH}/1098765/messages").respond(200, json={})
    journal = FlakyJournal(gateway)
    with TestClient(create_app(journal_transport=journal)) as c:
        journal.fail_actions = set()   # everything fails from now on
        r = c.post("/api/whatsapp/messages", json={"to": "1", "text": "hi"})
        webhook = c.post("/webhooks/alertmanager", json={"alerts": [{"status": "firing", "labels": {}}]})
        assert c.get("/ready").json()["checks"]["audit_journal_reachable"] is True  # gateway up, S3 down
    assert r.status_code == 503 and "fail-closed" in r.json()["error"]
    assert not meta.called
    assert webhook.status_code == 503           # sender (Meta / Alertmanager) will redeliver
    local = [json.loads(x) for x in fresh_audit_log.read_text().splitlines()]
    markers = [x for x in local if x["action"] == "audit.journal.write_failed"]
    assert markers and markers[0]["details"]["failed_seq"] is not None


@respx.mock
def test_outcome_unrecorded_is_flagged_not_hidden(gateway, journaled_env):
    respx.post(f"{GRAPH}/1098765/messages").respond(200, json={"messages": [{"id": "wamid.2"}]})
    journal = FlakyJournal(gateway)
    with TestClient(create_app(journal_transport=journal)) as c:
        journal.fail_actions = {"meta.api.post"}   # intent lands, outcome can't
        r = c.post("/api/whatsapp/messages", json={"to": "1", "text": "hi"})
    # The message was sent (intent is durable), so the client gets the real result, not a lie.
    assert r.status_code == 200 and r.json()["messages"][0]["id"] == "wamid.2"


def test_startup_refused_without_journal(journaled_env, monkeypatch):
    import app.main as main_mod
    monkeypatch.setattr(main_mod.asyncio, "sleep", lambda *_: _noop())
    dead = httpx.MockTransport(lambda req: httpx.Response(503))
    with pytest.raises(Exception):
        with TestClient(create_app(journal_transport=dead)):
            pass


async def _noop():
    return None


# ---------- verifier ----------
def test_verifier_flags_records_that_bypassed_the_gateway(gateway, s3, journaled_env, shipper_settings,
                                                          fresh_audit_log):
    with TestClient(create_app(journal_transport=httpx.ASGITransport(app=gateway))) as c:
        c.get("/api/rate-limits")
    # Someone with write access to the host appends a well-chained record directly to the file.
    AuditLog(str(fresh_audit_log)).record("meta.api.post", actor="injected")
    shipper = Shipper(shipper_settings, s3=s3)
    while shipper.ship_once():
        pass
    report = verify_archive(shipper_settings, s3=s3, compare_local=str(fresh_audit_log))
    injected = [x["seq"] for x in map(json.loads, fresh_audit_log.read_text().splitlines())
                if x["actor"] == "injected"]
    assert report["ok"] is False and report["not_journaled"] == injected
    assert report["journal_mismatches"] == []


def test_refusal_is_bounded_by_total_budget(journaled_env, monkeypatch):
    import asyncio
    import time

    from app.audit import AuditUnavailable, JournalClient

    async def slow(request):
        await asyncio.sleep(5)
        return httpx.Response(201, json={})

    async def run():
        client = JournalClient("http://gateway", TOKEN, timeout=0.3, retries=5,
                               transport=httpx.MockTransport(slow))
        start = time.monotonic()
        with pytest.raises(AuditUnavailable):
            await client.put({"seq": 1, "action": "x"})
        return time.monotonic() - start

    assert asyncio.run(run()) < 0.6


def test_gateway_ready_reflects_s3_failures(gateway, s3, tmp_path):
    c = TestClient(gateway)
    assert c.get("/ready").status_code == 200
    rec = make_record(tmp_path / "g.jsonl")
    from unittest.mock import patch
    from botocore.exceptions import EndpointConnectionError
    with patch.object(s3, "put_object", side_effect=EndpointConnectionError(endpoint_url="http://s3")):
        assert c.post("/v1/journal", json=rec, headers={"authorization": f"Bearer {TOKEN}"}).status_code == 503
    assert c.get("/ready").status_code == 503
    assert c.post("/v1/journal", json=rec, headers={"authorization": f"Bearer {TOKEN}"}).status_code == 201
    assert c.get("/ready").status_code == 200


def test_gateway_hard_deadline_on_hung_s3(gateway, s3, tmp_path, shipper_settings):
    import time
    from unittest.mock import patch
    shipper_settings.audit_journal_put_timeout_seconds = 0.2
    rec = make_record(tmp_path / "g.jsonl")
    c = TestClient(gateway)
    with patch.object(s3, "put_object", side_effect=lambda **kw: time.sleep(1)):
        start = time.monotonic()
        r = c.post("/v1/journal", json=rec, headers={"authorization": f"Bearer {TOKEN}"})
        assert r.status_code == 503 and time.monotonic() - start < 0.6
        assert c.get("/ready").status_code == 503
