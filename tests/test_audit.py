import json

import pytest
import respx
from fastapi.testclient import TestClient

from app.audit import AuditLog
from app.config import get_settings
from app.main import create_app

BASE = "https://graph.test/v24.0"


@pytest.fixture
def tc():
    with TestClient(create_app()) as c:
        yield c


def records(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_chain_verifies_and_detects_tampering(tmp_path):
    log = AuditLog(str(tmp_path / "a.jsonl"))
    for i in range(5):
        log.record("test.action", n=i)
    assert log.verify() == {"ok": True, "records_checked": 5, "head_hash": log._prev_hash}

    lines = (tmp_path / "a.jsonl").read_text().splitlines()
    rec = json.loads(lines[2])
    rec["actor"] = "someone-else"
    lines[2] = json.dumps(rec)
    (tmp_path / "a.jsonl").write_text("\n".join(lines) + "\n")
    assert log.verify() == {"ok": False, "records_checked": 2, "first_bad_seq": 3}


def test_chain_detects_deleted_record(tmp_path):
    log = AuditLog(str(tmp_path / "a.jsonl"))
    for i in range(4):
        log.record("test.action", n=i)
    lines = (tmp_path / "a.jsonl").read_text().splitlines()
    del lines[1]
    (tmp_path / "a.jsonl").write_text("\n".join(lines) + "\n")
    assert log.verify()["ok"] is False


def test_chain_continues_across_restarts(tmp_path):
    AuditLog(str(tmp_path / "a.jsonl")).record("one")
    reopened = AuditLog(str(tmp_path / "a.jsonl"))
    reopened.record("two")
    assert reopened.verify()["records_checked"] == 2 and reopened.verify()["ok"]


@respx.mock
def test_meta_call_audited_and_correlated(tc, fresh_audit_log):
    respx.post(f"{BASE}/1098765/messages").respond(200, json={"messages": [{"id": "wamid.XYZ"}]})
    r = tc.post("/api/whatsapp/messages", json={"to": "15551234567", "text": "secret words"},
                headers={"x-actor": "qa-tester", "x-request-id": "req-123"})
    assert r.headers["x-request-id"] == "req-123"

    recs = [x for x in records(fresh_audit_log) if x["request_id"] == "req-123"]
    meta = next(x for x in recs if x["action"] == "meta.api.post")
    http = next(x for x in recs if x["action"] == "http.request")
    assert meta["actor"] == http["actor"] == "unverified:qa-tester"
    assert meta["details"]["result_object_ids"] == ["wamid.XYZ"]
    assert meta["details"]["body"]["sha256"]  # payload digested...
    raw = fresh_audit_log.read_text()
    assert "secret words" not in raw and "test-token" not in raw  # ...never stored verbatim


@respx.mock
def test_failed_meta_call_audited_with_error(tc, fresh_audit_log):
    respx.get(f"{BASE}/me").respond(400, json={"error": {"message": "expired", "code": 190,
                                                         "fbtrace_id": "FBT1"}})
    tc.get("/api/me")
    meta = next(x for x in records(fresh_audit_log) if x["action"] == "meta.api.get")
    assert meta["outcome"] == "failure"
    assert meta["details"]["meta_error"]["code"] == 190
    assert meta["details"]["meta_error"]["fbtrace_id"] == "FBT1"


def test_api_keys_enforced_and_identify_actor(monkeypatch, fresh_audit_log):
    monkeypatch.setenv("APP_API_KEYS", "alice:k-alice")
    get_settings.cache_clear()
    with TestClient(create_app()) as c:
        assert c.get("/api/audit").status_code == 401
        assert c.get("/api/audit", headers={"x-api-key": "k-alice"}).status_code == 200
    http = [x for x in records(fresh_audit_log) if x["action"] == "http.request"]
    assert [(x["outcome"], x["actor"]) for x in http] == [("denied", "unauthenticated"),
                                                           ("success", "alice")]


def test_alertmanager_notifications_audited(tc, fresh_audit_log):
    tc.post("/webhooks/alertmanager", json={"receiver": "slack-critical", "groupKey": "g", "alerts": [
        {"status": "firing", "labels": {"alertname": "MetaApiCircuitOpen", "severity": "critical"},
         "annotations": {"summary": "circuit open"}, "fingerprint": "abc", "startsAt": "2026-09-29T00:00:00Z"}]})
    rec = next(x for x in records(fresh_audit_log) if x["action"] == "alert.notification")
    assert rec["actor"] == "alertmanager" and rec["resource"] == "MetaApiCircuitOpen"
    assert rec["details"]["receiver"] == "slack-critical"


def test_probes_not_audited_and_audit_api_verifies(tc, fresh_audit_log):
    tc.get("/health"); tc.get("/metrics"); tc.get("/ready")
    assert not [x for x in records(fresh_audit_log) if x["action"] == "http.request"]
    assert tc.get("/api/audit/verify").json()["ok"] is True
    assert tc.get("/api/audit", params={"action": "app"}).json()[0]["action"] == "app.started"


def test_ready_fails_when_audit_unwritable(tc, fresh_audit_log):
    assert tc.get("/ready").json()["checks"]["audit_log_writable"] is True
    fresh_audit_log.chmod(0o444)
    try:
        tc.get("/api/rate-limits")  # write attempt fails
        body = tc.get("/ready").json()
        assert body["checks"]["audit_log_writable"] is False and body["ready"] is False
    finally:
        fresh_audit_log.chmod(0o644)
