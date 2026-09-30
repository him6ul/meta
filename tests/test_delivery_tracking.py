import hashlib
import hmac
import json
import time

import respx
from fastapi.testclient import TestClient
from prometheus_client import REGISTRY

from app.main import create_app

GRAPH = "https://graph.test/v24.0"


def status_hook(wamid, status, ts=None, error=None):
    st = {"id": wamid, "status": status, "timestamp": str(int(ts or time.time())), "recipient_id": "1"}
    if error:
        st["errors"] = [error]
    body = json.dumps({"object": "whatsapp_business_account", "entry": [{"id": "W", "changes": [
        {"field": "messages", "value": {"statuses": [st]}}]}]}).encode()
    return {"content": body, "headers": {"content-type": "application/json", "x-hub-signature-256":
            "sha256=" + hmac.new(b"test-secret", body, hashlib.sha256).hexdigest()}}


@respx.mock
def test_status_lifecycle_latency_and_out_of_order():
    respx.post(f"{GRAPH}/1098765/messages").respond(200, json={"messages": [{"id": "wamid.T1"}]})
    before = REGISTRY.get_sample_value("whatsapp_status_latency_seconds_count", {"status": "read"}) or 0
    with TestClient(create_app()) as c:
        c.post("/api/whatsapp/messages", json={"to": "15551234567", "text": "hi"})
        assert c.get("/api/whatsapp/messages/wamid.T1/status").json()["status"] == "accepted"
        now = time.time()
        c.post("/webhooks/meta", **status_hook("wamid.T1", "sent", now + 1))
        c.post("/webhooks/meta", **status_hook("wamid.T1", "read", now + 5))
        c.post("/webhooks/meta", **status_hook("wamid.T1", "delivered", now + 3))   # late, out of order
        row = c.get("/api/whatsapp/messages/wamid.T1/status").json()
        stats = c.get("/api/whatsapp/delivery-stats").json()
    assert row["status"] == "read" and row["read_at"] and row["delivered_at"] is None
    assert stats["delivery_rate"] == 1.0 and stats["by_status"] == {"read": 1}
    assert REGISTRY.get_sample_value("whatsapp_status_latency_seconds_count", {"status": "read"}) == before + 1


@respx.mock
def test_failure_recorded_with_reason_and_audited(fresh_audit_log):
    respx.post(f"{GRAPH}/1098765/messages").respond(200, json={"messages": [{"id": "wamid.F1"}]})
    with TestClient(create_app()) as c:
        c.post("/api/whatsapp/messages", json={"to": "1", "text": "hi"})
        c.post("/webhooks/meta", **status_hook("wamid.F1", "failed",
                                                error={"code": 131026, "title": "Message undeliverable"}))
        c.post("/webhooks/meta", **status_hook("wamid.F1", "delivered"))   # can't un-fail
        row = c.get("/api/whatsapp/messages/wamid.F1/status").json()
        stats = c.get("/api/whatsapp/delivery-stats").json()
    assert row["status"] == "failed" and row["error_code"] == "131026"
    assert stats["top_failures"] == [{"code": "131026", "title": "Message undeliverable", "count": 1}]
    audited = [json.loads(x) for x in fresh_audit_log.read_text().splitlines()]
    assert any(r["action"] == "whatsapp.message.failed" and r["resource"] == "wamid.F1" for r in audited)


def test_stale_messages_counted(tmp_path):
    from app.delivery_tracker import DeliveryTracker
    t = DeliveryTracker(str(tmp_path / "d.sqlite"), stale_after_seconds=0.1)
    t.on_sent("wamid.S", "text")
    time.sleep(0.2)
    t.refresh_gauges()
    assert t.stale_count() == 1
    assert REGISTRY.get_sample_value("whatsapp_messages_stale_undelivered") == 1
