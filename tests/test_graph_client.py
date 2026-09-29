import hashlib
import hmac
import json

import httpx
import pytest
import respx
from prometheus_client import REGISTRY

from app.config import get_settings
from app.graph_client import CircuitBreaker, CircuitOpenError, MetaAPIError, MetaGraphClient

BASE = "https://graph.test/v24.0"


def metric(name, **labels):
    return REGISTRY.get_sample_value(name, labels) or 0.0


def err(status, code, **extra):
    return httpx.Response(status, json={"error": {"message": "x", "type": "OAuthException",
                                                  "code": code, **extra}})


@pytest.fixture
async def client():
    c = MetaGraphClient(get_settings())
    yield c
    await c.aclose()


@respx.mock
async def test_success_sends_token_and_appsecret_proof(client):
    route = respx.get(f"{BASE}/me").respond(200, json={"id": "1"},
                                            headers={"x-app-usage": json.dumps({"call_count": 42})})
    assert await client.get("/me") == {"id": "1"}
    params = route.calls[0].request.url.params
    assert params["access_token"] == "test-token"
    assert params["appsecret_proof"] == hmac.new(b"test-secret", b"test-token", hashlib.sha256).hexdigest()
    assert metric("meta_api_rate_limit_usage_percent", header="x-app-usage", scope_id="app",
                  usage_type="app", metric="call_count") == 42


@respx.mock
async def test_retries_transient_then_succeeds(client):
    before = metric("meta_api_retries_total", endpoint="/{id}/messages", reason="throttled")
    respx.post(f"{BASE}/1098765/messages").mock(side_effect=[err(400, 4), httpx.Response(200, json={"ok": 1})])
    assert await client.post("/1098765/messages", json_body={}) == {"ok": 1}
    assert metric("meta_api_retries_total", endpoint="/{id}/messages", reason="throttled") == before + 1


@respx.mock
async def test_non_retryable_error_raises_immediately(client):
    route = respx.get(f"{BASE}/me").mock(return_value=err(400, 190, error_subcode=463))
    with pytest.raises(MetaAPIError) as exc:
        await client.get("/me")
    assert exc.value.code == 190 and exc.value.subcode == 463
    assert route.call_count == 1
    assert client.breaker.state == CircuitBreaker.CLOSED  # caller errors don't trip the breaker


@respx.mock
async def test_business_use_case_header_parsed(client):
    buc = {"555": [{"type": "whatsapp", "call_count": 80, "total_cputime": 10, "total_time": 12,
                    "estimated_time_to_regain_access": 3}]}
    respx.get(f"{BASE}/me").respond(200, json={}, headers={"x-business-use-case-usage": json.dumps(buc)})
    await client.get("/me")
    assert metric("meta_api_rate_limit_usage_percent", header="x-business-use-case-usage",
                  scope_id="555", usage_type="whatsapp", metric="call_count") == 80
    assert metric("meta_api_rate_limit_regain_access_minutes", scope_id="555", usage_type="whatsapp") == 3


@respx.mock
async def test_circuit_opens_after_repeated_server_failures(client):
    respx.get(f"{BASE}/me").mock(return_value=err(500, 2, is_transient=True))
    for _ in range(3):
        with pytest.raises(MetaAPIError):
            await client.get("/me")
    assert client.breaker.state == CircuitBreaker.OPEN
    with pytest.raises(CircuitOpenError):
        await client.get("/me")


@respx.mock
async def test_network_error_retried_then_raised(client):
    route = respx.get(f"{BASE}/me").mock(side_effect=httpx.ConnectError("boom"))
    with pytest.raises(httpx.ConnectError):
        await client.get("/me")
    assert route.call_count == 3  # 1 + META_MAX_RETRIES
