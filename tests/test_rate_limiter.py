import json
import time

import pytest
import respx
from fastapi.testclient import TestClient

from app.config import get_settings
from app.main import create_app
from app.rate_limiter import LocalRateLimited, MetaRateLimiter

GRAPH = "https://graph.test/v24.0"


@pytest.fixture
def limiter():
    s = get_settings().model_copy(update={"meta_rate_max_wait_seconds": 0.05, "wa_messages_per_second": 5,
                                          "wa_pair_rate_per_second": 1, "wa_pair_burst": 2,
                                          "meta_rate_max_delay_seconds": 0.2})
    return MetaRateLimiter(s)


async def test_below_soft_no_delay(limiter):
    limiter.observe({"app": {"call_count": 50}})
    assert await limiter.before_call("GET", "/me", None) == 0


async def test_soft_zone_delays_proportionally(limiter):
    limiter.observe({"app": {"call_count": 90, "total_time": 10}})   # halfway between 80 and 95
    waited = await limiter.before_call("GET", "/me", None)
    assert 0.1 < waited < 0.15


async def test_hard_and_regain_refuse_without_calling(limiter):
    limiter.observe({"app": {"call_count": 97}})
    with pytest.raises(LocalRateLimited) as exc:
        await limiter.before_call("GET", "/me", None)
    assert exc.value.reason == "usage_hard"

    fresh = MetaRateLimiter(limiter.s)
    fresh.observe({"business_use_case": {"123": [{"type": "whatsapp", "call_count": 10,
                                                  "estimated_time_to_regain_access": 2}]}})
    with pytest.raises(LocalRateLimited) as exc:
        await fresh.before_call("POST", "/1098765/messages", {"to": "1"})
    assert exc.value.reason == "regain_access" and 110 < exc.value.retry_after <= 120
    # A WhatsApp BUC throttle must not block unrelated calls (e.g. the token health check).
    assert await fresh.before_call("GET", "/debug_token", None) == 0
    assert await fresh.before_call("GET", "/2000001/posts", None) == 0


async def test_stale_reading_does_not_lock_out(limiter):
    limiter.observe({"app": {"call_count": 99}})
    limiter.usage["app"] = (99.0, time.time() - limiter.s.meta_usage_stale_seconds - 1)
    assert await limiter.before_call("GET", "/me", None) == 0


async def test_pair_limit_per_recipient(limiter):
    body = {"to": "15550001"}
    await limiter.before_call("POST", "/1098765/messages", body)
    await limiter.before_call("POST", "/1098765/messages", body)       # burst of 2
    with pytest.raises(LocalRateLimited) as exc:
        await limiter.before_call("POST", "/1098765/messages", body)
    assert exc.value.reason == "wa_pair"
    await limiter.before_call("POST", "/1098765/messages", {"to": "15550002"})  # other recipient fine


async def test_phone_throughput_bucket(limiter):
    for i in range(5):
        await limiter.before_call("POST", "/1098765/messages", {"to": str(i)})
    with pytest.raises(LocalRateLimited) as exc:
        await limiter.before_call("POST", "/1098765/messages", {"to": "99"})
    assert exc.value.reason == "wa_throughput"


@respx.mock
def test_app_returns_429_retry_after_and_never_calls_meta(monkeypatch, fresh_audit_log):
    monkeypatch.setenv("WA_PAIR_BURST", "1")
    monkeypatch.setenv("META_RATE_MAX_WAIT_SECONDS", "0.1")
    get_settings.cache_clear()
    meta = respx.post(f"{GRAPH}/1098765/messages").respond(200, json={"messages": [{"id": "wamid.R"}]})
    with TestClient(create_app()) as c:
        assert c.post("/api/whatsapp/messages", json={"to": "1", "text": "a"}).status_code == 200
        r = c.post("/api/whatsapp/messages", json={"to": "1", "text": "b"})
    assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1 and r.json()["source"] == "local"
    assert meta.call_count == 1
    recs = [json.loads(x) for x in fresh_audit_log.read_text().splitlines()]
    assert any(x["action"] == "meta.api.post" and x["outcome"] == "local_rate_limited" for x in recs)


async def test_buc_usage_only_paces_its_own_product(limiter):
    limiter.observe({"business_use_case": {"1": [{"type": "whatsapp", "call_count": 99}]}})
    with pytest.raises(LocalRateLimited):
        await limiter.before_call("POST", "/1098765/messages", {"to": "1"})
    assert await limiter.before_call("GET", "/me", None) == 0
