"""Contract tests against the REAL Meta Graph API (sandbox / test assets).

Skipped unless META_LIVE_ACCESS_TOKEN is set. They catch what the mock can't: API version changes,
error-shape changes, header format changes, permission drift.

  META_LIVE_ACCESS_TOKEN      token for a test app / system user (required)
  META_LIVE_APP_ID/SECRET     enables appsecret_proof + app-token debug_token checks
  META_LIVE_API_VERSION       default: the app's META_API_VERSION
  META_LIVE_WA_PHONE_ID       WhatsApp test phone number id (read-only checks)
  META_LIVE_WA_TO             ALSO set this to actually send the `hello_world` template to a
                              recipient on the test number's allow-list (sends a real message)
  META_LIVE_REQUIRED_SCOPES   comma list that the token must have

Run: make contract   (or: pytest -m live tests/contract)
"""
import os

import pytest

from app.config import Settings
from app.graph_client import MetaAPIError, MetaGraphClient

pytestmark = [pytest.mark.live,
              pytest.mark.skipif(not os.getenv("META_LIVE_ACCESS_TOKEN"),
                                 reason="META_LIVE_ACCESS_TOKEN not set (live contract tests are opt-in)")]


@pytest.fixture
async def live():
    base = Settings()
    settings = base.model_copy(update={
        "meta_graph_base_url": "https://graph.facebook.com",
        "meta_api_version": os.getenv("META_LIVE_API_VERSION", base.meta_api_version),
        "meta_access_token": os.environ["META_LIVE_ACCESS_TOKEN"],
        "meta_app_id": os.getenv("META_LIVE_APP_ID", ""),
        "meta_app_secret": os.getenv("META_LIVE_APP_SECRET", ""),
        "meta_max_retries": 1, "meta_backoff_base_seconds": 1.0,
    })
    client = MetaGraphClient(settings)   # no audit: contract tests don't touch the audit trail
    yield client
    await client.aclose()


async def test_me_shape(live):
    me = await live.get("/me", params={"fields": "id,name"})
    assert me["id"].isdigit()


async def test_token_valid_with_required_scopes(live):
    s = live.settings
    inspector = f"{s.meta_app_id}|{s.meta_app_secret}" if s.meta_app_id and s.meta_app_secret else None
    data = (await live.get("/debug_token", params={"input_token": s.meta_access_token}, token=inspector))["data"]
    assert data["is_valid"] is True, data.get("error")
    required = {x for x in os.getenv("META_LIVE_REQUIRED_SCOPES", "").split(",") if x}
    assert required <= set(data.get("scopes", [])), f"missing scopes: {required - set(data.get('scopes', []))}"
    if data.get("expires_at"):
        import time
        assert data["expires_at"] - time.time() > 7 * 86400, "token expires within 7 days"


async def test_error_shape_is_what_the_client_parses(live):
    with pytest.raises(MetaAPIError) as exc:
        await live.get("/me", params={"fields": "definitely_not_a_field"})
    err = exc.value
    assert err.status == 400 and err.code == 100 and err.type and err.fbtrace_id


async def test_usage_headers_parse(live):
    await live.get("/me")
    # Meta returns X-App-Usage (or BUC headers for business assets); the parser must understand them.
    assert live.last_usage, "no rate-limit usage headers parsed from a live response"


@pytest.mark.skipif(not os.getenv("META_LIVE_WA_PHONE_ID"), reason="META_LIVE_WA_PHONE_ID not set")
async def test_whatsapp_phone_number_readable(live):
    phone = await live.get(f"/{os.environ['META_LIVE_WA_PHONE_ID']}",
                           params={"fields": "display_phone_number,quality_rating,verified_name"})
    assert phone.get("display_phone_number")


@pytest.mark.skipif(not (os.getenv("META_LIVE_WA_PHONE_ID") and os.getenv("META_LIVE_WA_TO")),
                    reason="set META_LIVE_WA_PHONE_ID and META_LIVE_WA_TO to send a real test message")
async def test_whatsapp_send_template(live):
    resp = await live.post(f"/{os.environ['META_LIVE_WA_PHONE_ID']}/messages", json_body={
        "messaging_product": "whatsapp", "to": os.environ["META_LIVE_WA_TO"], "type": "template",
        "template": {"name": "hello_world", "language": {"code": "en_US"}}})
    assert resp["messages"][0]["id"].startswith("wamid.")
