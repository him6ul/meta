import hashlib
import hmac
import json

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from app.main import create_app
from app.metrics import normalize_endpoint

BASE = "https://graph.test/v24.0"


@pytest.fixture
def tc():
    with TestClient(create_app()) as c:
        yield c


def test_normalize_endpoint():
    assert normalize_endpoint("/v24.0/1234/messages") == "/{id}/messages"
    assert normalize_endpoint("/act_987/insights") == "/{id}/insights"
    assert normalize_endpoint("/me") == "/me"


def test_health_ready_metrics(tc):
    assert tc.get("/health").json() == {"status": "ok"}
    assert tc.get("/ready").status_code == 200
    body = tc.get("/metrics").text
    assert "meta_api_circuit_state" in body


@respx.mock
def test_whatsapp_send(tc):
    route = respx.post(f"{BASE}/1098765/messages").respond(200, json={"messages": [{"id": "wamid.1"}]})
    r = tc.post("/api/whatsapp/messages", json={"to": "15551234567", "text": "hi"})
    assert r.status_code == 200
    sent = json.loads(route.calls[0].request.content)
    assert sent["messaging_product"] == "whatsapp" and sent["text"]["body"] == "hi"


@respx.mock
def test_throttle_maps_to_429(tc):
    respx.get(f"{BASE}/me").respond(400, json={"error": {"message": "limit", "code": 4}})
    r = tc.get("/api/me")
    assert r.status_code == 429
    assert r.json()["error"]["code"] == 4


def test_webhook_verification(tc):
    ok = tc.get("/webhooks/meta", params={"hub.mode": "subscribe", "hub.verify_token": "verify-me",
                                          "hub.challenge": "12345"})
    assert ok.status_code == 200 and ok.text == "12345"
    bad = tc.get("/webhooks/meta", params={"hub.mode": "subscribe", "hub.verify_token": "nope",
                                           "hub.challenge": "1"})
    assert bad.status_code == 403


def test_webhook_signature(tc):
    body = json.dumps({"object": "page", "entry": [{"id": "1", "messaging": [{}]}]}).encode()
    sig = "sha256=" + hmac.new(b"test-secret", body, hashlib.sha256).hexdigest()
    ok = tc.post("/webhooks/meta", content=body, headers={"x-hub-signature-256": sig,
                                                          "content-type": "application/json"})
    assert ok.status_code == 200
    bad = tc.post("/webhooks/meta", content=body, headers={"x-hub-signature-256": "sha256=deadbeef",
                                                           "content-type": "application/json"})
    assert bad.status_code == 401
    assert tc.get("/webhooks/meta/recent").json()[0]["signature"] == "valid"
