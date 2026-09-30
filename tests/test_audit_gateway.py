"""Gateway sequencing: one global chain across app replicas, group commit, CAS-based safety, fail-closed."""
import asyncio
import json
import threading
import uuid

import boto3
import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from moto import mock_aws
from prometheus_client import REGISTRY

from app.audit_gateway import (BlockStore, GatewaySettings, RecordIndex, Sequencer, create_gateway,
                               verify_archive)
from app.config import get_settings
from app.main import create_app

BUCKET = "gw-test"
TOKEN = "gw-token"
AUTH = {"authorization": f"Bearer {TOKEN}"}
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
def gw_settings(tmp_path):
    return GatewaySettings(audit_s3_bucket=BUCKET, audit_s3_retention_days=1, audit_journal_token=TOKEN,
                           audit_gateway_state_dir=str(tmp_path / "gw1"), audit_commit_window_seconds=0.02,
                           audit_commit_deadline_seconds=3)


@pytest.fixture
def gateway(s3, gw_settings):
    app = create_gateway(gw_settings, s3=s3, gateway_id="gw-1")
    yield app
    app.state.sequencer.stop()


def draft(action="test.action", replica="r1", **extra):
    return {"ts": "2026-09-30T00:00:00+00:00", "action": action, "outcome": "success", "actor": "t",
            "replica": replica, "draft_id": uuid.uuid4().hex, "details": {}, **extra}


def blocks(s3):
    return sorted(o["Key"] for o in s3.list_objects_v2(Bucket=BUCKET).get("Contents", []))


# ---------- sequencing ----------
def test_concurrent_drafts_from_many_replicas_form_one_chain_in_few_blocks(gateway, s3, gw_settings):
    c = TestClient(gateway)
    results = []

    def send(i):
        results.append(c.post("/v2/records", json=draft(replica=f"r{i % 3}"), headers=AUTH).json())

    threads = [threading.Thread(target=send, args=(i,)) for i in range(40)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sorted(r["seq"] for r in results) == list(range(1, 41))   # contiguous, no duplicates
    assert len(blocks(s3)) < 40                                       # group commit batched them
    report = verify_archive(gw_settings, s3=s3)
    assert report["ok"] and report["head_seq"] == 40 and set(report["records_by_replica"]) == {"r0", "r1", "r2"}


def test_retry_with_same_draft_id_is_idempotent(gateway, s3):
    c = TestClient(gateway)
    d = draft()
    first = c.post("/v2/records", json=d, headers=AUTH).json()
    again = c.post("/v2/records", json=d, headers=AUTH).json()
    assert first == again and len(blocks(s3)) == 1


def test_drafts_cannot_choose_their_own_seq_and_need_auth(gateway):
    c = TestClient(gateway)
    assert c.post("/v2/records", json=draft()).status_code == 401
    assert c.post("/v2/records", json={**draft(), "seq": 99}, headers=AUTH).status_code == 400
    assert c.post("/v2/records", json={"action": "x"}, headers=AUTH).status_code == 400   # no draft_id


def test_two_gateways_on_one_bucket_never_fork(s3, gw_settings, tmp_path):
    """Split-brain: both gateways accept writes. CAS on block slots keeps a single chain."""
    a = create_gateway(gw_settings, s3=s3, gateway_id="gw-a")
    b = create_gateway(gw_settings.model_copy(update={"audit_gateway_state_dir": str(tmp_path / "gw2")}),
                       s3=s3, gateway_id="gw-b")
    ca, cb = TestClient(a), TestClient(b)
    before = REGISTRY.get_sample_value("audit_gateway_sequencer_conflicts_total") or 0
    out = []
    for i in range(10):
        out.append((ca if i % 2 == 0 else cb).post("/v2/records", json=draft(), headers=AUTH).json()["seq"])
    a.state.sequencer.stop(); b.state.sequencer.stop()
    assert sorted(out) == list(range(1, 11))
    assert REGISTRY.get_sample_value("audit_gateway_sequencer_conflicts_total") > before
    assert verify_archive(gw_settings, s3=s3)["ok"]


def test_restart_recovers_head_from_s3_without_index(gateway, s3, gw_settings, tmp_path):
    c = TestClient(gateway)
    for _ in range(3):
        c.post("/v2/records", json=draft(), headers=AUTH)
    gateway.state.sequencer.stop()
    fresh = create_gateway(gw_settings.model_copy(update={"audit_gateway_state_dir": str(tmp_path / "empty")}),
                           s3=s3, gateway_id="gw-new")
    rec = TestClient(fresh).post("/v2/records", json=draft(), headers=AUTH).json()
    fresh.state.sequencer.stop()
    assert rec["seq"] == 4 and verify_archive(gw_settings, s3=s3)["ok"]


def test_unknown_commit_outcome_is_resolved_before_reusing_the_slot(s3, gw_settings):
    """A timed-out write that lands later is adopted into the chain, never overwritten or forked."""
    index = RecordIndex(":memory:")
    store = BlockStore(gw_settings, s3)
    seq = Sequencer(gw_settings, store, index, "gw-x")
    # Simulate: our block 1 write timed out from our point of view but actually landed.
    ghost = seq._chain([draft()])
    from app.audit_gateway import canonical_line
    store.put(1, b"".join(canonical_line(r) for r in ghost), ghost, "gw-x")
    seq.uncertain = True
    seq.start()
    rec = seq.submit(draft(), timeout=3).result(timeout=5)
    seq.stop()
    assert rec["seq"] == 2 and rec["prev_hash"] == ghost[0]["hash"]
    assert verify_archive(gw_settings, s3=s3)["ok"]


def test_s3_outage_fails_fast_and_marks_not_ready(gateway, s3):
    from unittest.mock import patch

    from botocore.exceptions import EndpointConnectionError
    c = TestClient(gateway)
    with patch.object(s3, "put_object", side_effect=EndpointConnectionError(endpoint_url="http://s3")):
        assert c.post("/v2/records", json=draft(), headers=AUTH).status_code == 503
        assert c.get("/ready").status_code == 503
    assert c.post("/v2/records", json=draft(), headers=AUTH).status_code == 201
    assert c.get("/ready").status_code == 200


def test_query_api_is_global(gateway):
    c = TestClient(gateway)
    c.post("/v2/records", json=draft("a.one", replica="r1"), headers=AUTH)
    c.post("/v2/records", json=draft("a.two", replica="r2"), headers=AUTH)
    assert [r["action"] for r in c.get("/v2/records", params={"action": "a"}, headers=AUTH).json()] == ["a.two", "a.one"]
    assert len(c.get("/v2/records", params={"replica": "r2"}, headers=AUTH).json()) == 1


# ---------- app replicas end to end ----------
@pytest.fixture
def replicas(gateway, monkeypatch, tmp_path):
    monkeypatch.setenv("AUDIT_JOURNAL_URL", "http://gateway")
    monkeypatch.setenv("AUDIT_JOURNAL_TOKEN", TOKEN)
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "audit-{replica}.jsonl"))

    def make(name):
        monkeypatch.setenv("APP_REPLICA_ID", name)
        get_settings.cache_clear()
        return create_app(journal_transport=httpx.ASGITransport(app=gateway))
    return make


@respx.mock
def test_two_app_replicas_share_one_chain(replicas, gateway, s3, gw_settings, tmp_path):
    respx.post(f"{GRAPH}/1098765/messages").respond(200, json={"messages": [{"id": "wamid.1"}]})
    app_a, app_b = replicas("replica-a"), replicas("replica-b")
    with TestClient(app_a) as a, TestClient(app_b) as b:
        for i in range(3):
            (a if i % 2 == 0 else b).post("/api/whatsapp/messages", json={"to": f"1{i}", "text": "hi"})
        everything = a.get("/api/audit", params={"limit": 200}).json()      # global view from replica A
        verify_a = a.get("/api/audit/verify").json()
    assert {r["replica"] for r in everything} == {"replica-a", "replica-b"}
    cache_a = [json.loads(x) for x in (tmp_path / "audit-replica-a.jsonl").read_text().splitlines()]
    cache_b = [json.loads(x) for x in (tmp_path / "audit-replica-b.jsonl").read_text().splitlines()]
    assert {r["replica"] for r in cache_a} == {"replica-a"} and {r["replica"] for r in cache_b} == {"replica-b"}
    seqs = sorted(r["seq"] for r in cache_a + cache_b)
    assert seqs == list(range(1, len(seqs) + 1))                        # interleaved into one gapless chain
    assert verify_a["replica_cache"]["mismatched_seqs"] == [] and verify_a["replica_cache"]["unknown_to_gateway"] == []
    report = verify_archive(gw_settings, s3=s3, compare_local=[str(tmp_path / "audit-replica-a.jsonl"),
                                                              str(tmp_path / "audit-replica-b.jsonl")])
    assert report["ok"], report["findings"]
    # write-ahead ordering still holds within each request
    by_action = {}
    for r in cache_a:
        by_action.setdefault(r["action"], r)
    assert by_action["meta.api.post"]["details"]["intent_seq"] == by_action["meta.api.post.intent"]["seq"]


def test_injected_local_record_is_flagged(replicas, gateway, s3, gw_settings, tmp_path):
    with TestClient(replicas("replica-a")) as a:
        a.get("/api/rate-limits")
    cache = tmp_path / "audit-replica-a.jsonl"
    forged = json.loads(cache.read_text().splitlines()[-1])
    forged.update(seq=forged["seq"] + 100, actor="injected")
    with cache.open("a") as f:
        f.write(json.dumps(forged) + "\n")
    report = verify_archive(gw_settings, s3=s3, compare_local=[str(cache)])
    assert not report["ok"] and report["local"]["not_in_archive"][0]["seq"] == forged["seq"]


@respx.mock
def test_fail_closed_when_gateway_cannot_commit(replicas, gateway, s3):
    from unittest.mock import patch

    from botocore.exceptions import EndpointConnectionError
    meta = respx.post(f"{GRAPH}/1098765/messages").respond(200, json={})
    with TestClient(replicas("replica-a")) as a:
        with patch.object(s3, "put_object", side_effect=EndpointConnectionError(endpoint_url="http://s3")):
            r = a.post("/api/whatsapp/messages", json={"to": "1", "text": "hi"})
            hook = a.post("/webhooks/alertmanager", json={"alerts": [{"status": "firing", "labels": {}}]})
    assert r.status_code == 503 and "fail-closed" in r.json()["error"] and not meta.called
    assert hook.status_code == 503


def test_app_refuses_to_start_without_gateway(monkeypatch, tmp_path):
    import app.main as main_mod

    async def instant(*_):
        return None
    monkeypatch.setattr(main_mod.asyncio, "sleep", instant)
    monkeypatch.setenv("AUDIT_JOURNAL_URL", "http://gateway")
    monkeypatch.setenv("AUDIT_JOURNAL_TOKEN", TOKEN)
    get_settings.cache_clear()
    with pytest.raises(Exception):
        with TestClient(create_app(journal_transport=httpx.MockTransport(lambda r: httpx.Response(503)))):
            pass


def test_client_budget_bounds_refusal_time():
    import time

    from app.audit import AuditUnavailable, GatewayClient

    async def slow(request):
        await asyncio.sleep(5)
        return httpx.Response(201, json={})

    async def run():
        c = GatewayClient("http://gw", TOKEN, timeout=0.3, retries=5, transport=httpx.MockTransport(slow))
        start = time.monotonic()
        with pytest.raises(AuditUnavailable):
            await c.append({"action": "x", "draft_id": "d"})
        return time.monotonic() - start

    assert asyncio.run(run()) < 0.6
