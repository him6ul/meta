import hashlib
import hmac
import json
import time

import pytest
import respx
from fastapi.testclient import TestClient

from app.config import get_settings
from app.main import create_app
from app.webhook_dedup import WebhookDedup, event_keys

GRAPH = "https://graph.test/v24.0"


def signed(payload: dict, secret: bytes = b"test-secret") -> tuple[bytes, dict]:
    body = json.dumps(payload).encode()
    return body, {"content-type": "application/json",
                  "x-hub-signature-256": "sha256=" + hmac.new(secret, body, hashlib.sha256).hexdigest()}


def wa(messages=(), statuses=()):
    return {"object": "whatsapp_business_account", "entry": [{"id": "WABA", "changes": [{
        "field": "messages", "value": {"messages": [{"id": m} for m in messages],
                                       "statuses": [{"id": i, "status": st} for i, st in statuses]}}]}]}


@pytest.fixture
def tc():
    with TestClient(create_app()) as c:
        yield c


# ---------- dedup ----------
def test_event_keys_per_event_kind():
    keys = [e["key"] for e in event_keys(wa(["wamid.A"], [("wamid.B", "sent"), ("wamid.B", "delivered")]))]
    assert keys == ["msg:wamid.A", "status:wamid.B:sent", "status:wamid.B:delivered"]
    messenger = {"object": "page", "entry": [{"id": "P", "messaging": [{"message": {"mid": "m1"}}, {"read": {}}]}]}
    assert [e["key"].split(":")[0] for e in event_keys(messenger)] == ["mid", "ev"]


def test_redelivery_processed_once_and_survives_restart(fresh_audit_log):
    body, headers = signed(wa(["wamid.X"]))
    with TestClient(create_app()) as c:
        assert c.post("/webhooks/meta", content=body, headers=headers).json()["new"] == 1
        assert c.post("/webhooks/meta", content=body, headers=headers).json()["duplicates"] == 1
    with TestClient(create_app()) as c:   # restart: dedup state is on disk
        r = c.post("/webhooks/meta", content=body, headers=headers).json()
    assert (r["new"], r["duplicates"]) == (0, 1)


def test_batch_with_new_and_old_events_processes_only_new(tc):
    tc.post("/webhooks/meta", **dict(zip(("content", "headers"), signed(wa(["wamid.1"])))))
    r = tc.post("/webhooks/meta", **dict(zip(("content", "headers"), signed(wa(["wamid.1", "wamid.2"]))))).json()
    assert (r["new"], r["duplicates"]) == (1, 1)
    assert tc.get("/webhooks/meta/recent").json()[0]["new_events"] == ["msg:wamid.2"]


def test_failed_processing_leaves_event_eligible_for_redelivery(monkeypatch, fresh_audit_log):
    import app.webhooks as wh
    body, headers = signed(wa(["wamid.F"]))
    with TestClient(create_app(), raise_server_exceptions=False) as c:
        async def boom(*_):
            raise RuntimeError("downstream down")
        monkeypatch.setattr(wh, "process_events", boom)
        assert c.post("/webhooks/meta", content=body, headers=headers).status_code == 500
        monkeypatch.undo()
        assert c.post("/webhooks/meta", content=body, headers=headers).json()["new"] == 1


def test_dedup_ttl(tmp_path):
    d = WebhookDedup(str(tmp_path / "d.sqlite"), ttl_days=1 / 86400)  # 1 second
    d.mark(["k"])
    assert d.seen(["k"]) == {"k"}
    time.sleep(1.1)
    assert d.seen(["k"]) == set()


# ---------- signature required ----------
def test_unsigned_rejected_when_secret_missing(monkeypatch):
    monkeypatch.setenv("META_APP_SECRET", "")
    get_settings.cache_clear()
    with TestClient(create_app()) as c:
        r = c.post("/webhooks/meta", json=wa(["wamid.U"]))
        ready = c.get("/ready").json()
    assert r.status_code == 503                        # Meta keeps retrying until configured
    assert ready["checks"]["webhook_signature_configured"] is False and ready["ready"] is False


def test_unsigned_allowed_only_when_explicitly_opted_out(monkeypatch):
    monkeypatch.setenv("META_APP_SECRET", "")
    monkeypatch.setenv("META_WEBHOOK_REQUIRE_SIGNATURE", "false")
    get_settings.cache_clear()
    with TestClient(create_app()) as c:
        assert c.post("/webhooks/meta", json=wa(["wamid.U"])).status_code == 200


# ---------- token monitor ----------
@respx.mock
def test_token_status_reports_expiry_and_missing_scopes(monkeypatch):
    monkeypatch.setenv("META_REQUIRED_SCOPES", "whatsapp_business_messaging,pages_manage_posts")
    get_settings.cache_clear()
    expires = int(time.time()) + 3 * 86400
    route = respx.get(f"{GRAPH}/debug_token").respond(200, json={"data": {
        "is_valid": True, "type": "USER", "expires_at": expires, "data_access_expires_at": 0,
        "scopes": ["whatsapp_business_messaging"]}})
    with TestClient(create_app()) as c:
        status = c.get("/api/token-status").json()
        metrics = c.get("/metrics").text
    assert route.calls[0].request.url.params["access_token"] == "999|test-secret"  # app token inspects
    assert 2.9 < status["expires_in_days"] <= 3 and status["missing_required_scopes"] == ["pages_manage_posts"]
    assert "meta_token_missing_required_scopes 1.0" in metrics and "meta_token_valid 1.0" in metrics


@respx.mock
def test_token_invalid_sets_gauge(tc):
    respx.get(f"{GRAPH}/debug_token").respond(200, json={"data": {"is_valid": False, "scopes": [],
                                                                  "error": {"message": "Session expired"}}})
    status = tc.get("/api/token-status", params={"refresh": True}).json()
    assert status["is_valid"] is False and status["error"] == "Session expired"
    assert "meta_token_valid 0.0" in tc.get("/metrics").text
