"""A small fake of the Meta Graph API for local testing, with runtime fault injection.

Tune behaviour at runtime:
  curl -XPOST localhost:8081/_mock/config -H 'content-type: application/json' \
       -d '{"error_rate":0.2,"throttle_rate":0.1,"latency_ms":300}'
Send a signed webhook to the app:
  curl -XPOST localhost:8081/_mock/send-webhook
"""
import asyncio
import hashlib
import hmac
import json
import os
import random
import time
import uuid
from collections import deque
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel

app = FastAPI(title="Mock Meta Graph API")


class MockConfig(BaseModel):
    error_rate: float = float(os.getenv("MOCK_ERROR_RATE", "0.02"))      # -> 500 code 2 (transient)
    throttle_rate: float = float(os.getenv("MOCK_THROTTLE_RATE", "0.02"))  # -> 400 code 4 / 130429
    auth_error_rate: float = float(os.getenv("MOCK_AUTH_ERROR_RATE", "0.0"))  # -> 400 code 190
    latency_ms: int = int(os.getenv("MOCK_LATENCY_MS", "80"))
    latency_jitter_ms: int = int(os.getenv("MOCK_LATENCY_JITTER_MS", "120"))
    outage: bool = False                                                 # every call -> 503


CONFIG = MockConfig()
APP_SECRET = os.getenv("META_APP_SECRET", "")
WEBHOOK_TARGET = os.getenv("MOCK_WEBHOOK_TARGET", "http://app:8000/webhooks/meta")
SLACK_MESSAGES: deque = deque(maxlen=100)
_window_start = time.monotonic()
_window_calls = 0


def _usage_headers(path: str) -> dict[str, str]:
    """Emulate X-App-Usage / X-Business-Use-Case-Usage, which climb with call volume over a 60s window."""
    global _window_start, _window_calls
    now = time.monotonic()
    if now - _window_start > 60:
        _window_start, _window_calls = now, 0
    _window_calls += 1
    pct = min(100, _window_calls // 6)
    headers = {"x-app-usage": json.dumps({"call_count": pct, "total_cputime": pct // 2,
                                          "total_time": pct // 2})}
    if "messages" in path or "feed" in path or "posts" in path:
        utype = "whatsapp" if "messages" in path else "pages"
        headers["x-business-use-case-usage"] = json.dumps({"123456789": [{
            "type": utype, "call_count": pct, "total_cputime": pct // 3, "total_time": pct // 3,
            "estimated_time_to_regain_access": 0 if pct < 100 else 5,
        }]})
    return headers


def _error(status: int, code: int, message: str, etype: str = "OAuthException",
           subcode: int | None = None, transient: bool = False, headers=None) -> JSONResponse:
    err = {"message": message, "type": etype, "code": code, "is_transient": transient,
           "fbtrace_id": uuid.uuid4().hex[:11]}
    if subcode:
        err["error_subcode"] = subcode
    return JSONResponse(status_code=status, content={"error": err}, headers=headers)


@app.middleware("http")
async def faults(request: Request, call_next):
    if request.url.path.startswith("/_mock") or request.url.path == "/health":
        return await call_next(request)
    await asyncio.sleep(max(0, CONFIG.latency_ms + random.randint(0, CONFIG.latency_jitter_ms)) / 1000)
    headers = _usage_headers(request.url.path)
    if "access_token" not in request.query_params:
        return _error(400, 104, "An access token is required to request this resource.", headers=headers)
    if CONFIG.outage:
        return _error(503, 2, "Service temporarily unavailable", transient=True, headers=headers)
    r = random.random()
    if r < CONFIG.error_rate:
        return _error(500, 2, "An unexpected error has occurred. Please retry your request later.",
                      transient=True, headers=headers)
    r -= CONFIG.error_rate
    if r < CONFIG.throttle_rate:
        if "messages" in request.url.path:
            return _error(400, 130429, "Rate limit hit", headers=headers)
        return _error(400, 4, "Application request limit reached", headers=headers)
    r -= CONFIG.throttle_rate
    if r < CONFIG.auth_error_rate:
        return _error(400, 190, "Error validating access token: Session has expired.", subcode=463,
                      headers=headers)
    response = await call_next(request)
    for k, v in headers.items():
        response.headers[k] = v
    return response


# ---------- mock control ----------
@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/_mock/config")
async def get_config():
    return CONFIG


def audit(action: str, request: Request, **details) -> None:
    """Chaos changes alter what the system under test sees, so they are audited (JSON line on stdout)."""
    print(json.dumps({"audit": True, "ts": datetime.now(timezone.utc).isoformat(), "service": "mock-meta",
                      "action": action, "actor": request.headers.get("x-actor", "anonymous"),
                      "actor_ip": request.client.host if request.client else None, **details}), flush=True)


@app.post("/_mock/config")
async def set_config(update: dict, request: Request):
    global CONFIG
    before = CONFIG.model_dump()
    CONFIG = CONFIG.model_copy(update=update)
    audit("mock.config.changed", request, before=before, after=CONFIG.model_dump(), requested=update)
    return CONFIG


@app.post("/_mock/slack")
async def fake_slack(request: Request):
    """Stands in for a Slack incoming webhook so the alert path can be tested without Slack."""
    msg = await request.json()
    SLACK_MESSAGES.appendleft({"received_at": datetime.now(timezone.utc).isoformat(), "message": msg})
    print(json.dumps({"fake_slack": True, "attachments": [a.get("title") for a in msg.get("attachments", [])]}),
          flush=True)
    return PlainTextResponse("ok")


@app.get("/_mock/slack")
async def fake_slack_messages():
    return list(SLACK_MESSAGES)


@app.post("/_mock/send-webhook")
async def send_webhook(request: Request, valid_signature: bool = True):
    payload = {"object": "whatsapp_business_account", "entry": [{
        "id": "123456789", "changes": [{"field": "messages", "value": {
            "messaging_product": "whatsapp",
            "metadata": {"display_phone_number": "15550001111", "phone_number_id": "1098765"},
            "messages": [{"from": "15551234567", "id": f"wamid.{uuid.uuid4().hex}",
                          "timestamp": str(int(time.time())), "type": "text",
                          "text": {"body": "Hello from the mock"}}],
        }}],
    }]}
    body = json.dumps(payload).encode()
    secret = APP_SECRET if valid_signature else "wrong-secret"
    sig = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    async with httpx.AsyncClient(timeout=5) as c:
        r = await c.post(WEBHOOK_TARGET, content=body,
                         headers={"content-type": "application/json", "x-hub-signature-256": sig})
    audit("mock.webhook.sent", request, target=WEBHOOK_TARGET, valid_signature=valid_signature,
          response_status=r.status_code)
    return {"target": WEBHOOK_TARGET, "status": r.status_code, "response": r.text}


# ---------- Graph API surface ----------
@app.get("/{version}/me")
async def me(fields: str = "id,name"):
    data = {"id": "10001", "name": "Mock User", "email": "mock@example.com"}
    return {k: data[k] for k in fields.split(",") if k in data}


@app.get("/{version}/debug_token")
async def debug_token(input_token: str):
    return {"data": {"app_id": "999", "type": "SYSTEM_USER", "application": "Mock App",
                     "is_valid": True, "expires_at": 0, "data_access_expires_at": 0,
                     "scopes": ["whatsapp_business_messaging", "pages_read_engagement",
                                "pages_manage_posts", "instagram_basic"]}}


@app.post("/{version}/{phone_id}/messages")
async def wa_messages(phone_id: str, request: Request):
    body = await request.json()
    if body.get("messaging_product") != "whatsapp" or not body.get("to"):
        return _error(400, 100, "(#100) Invalid parameter")
    return {"messaging_product": "whatsapp", "contacts": [{"input": body["to"], "wa_id": body["to"]}],
            "messages": [{"id": f"wamid.{uuid.uuid4().hex}"}]}


@app.get("/{version}/{page_id}/posts")
async def page_posts(page_id: str, limit: int = 10):
    return {"data": [{"id": f"{page_id}_{i}", "message": f"Mock post {i}",
                      "created_time": "2026-09-01T12:00:00+0000"} for i in range(min(limit, 25))],
            "paging": {"cursors": {"before": "b", "after": "a"}}}


@app.post("/{version}/{page_id}/feed")
async def page_feed(page_id: str, message: str = ""):
    if not message:
        return _error(400, 100, "(#100) Missing message or attachment")
    return {"id": f"{page_id}_{random.randint(10**9, 10**10)}"}


@app.get("/{version}/{ig_id}/media")
async def ig_media(ig_id: str, limit: int = 10):
    return {"data": [{"id": str(17800000000 + i), "caption": f"Mock media {i}", "media_type": "IMAGE",
                      "timestamp": "2026-09-01T12:00:00+0000"} for i in range(min(limit, 25))]}


@app.get("/{version}/{object_id}")
async def generic_object(object_id: str, fields: str = "id,name"):
    return {"id": object_id, **{f: f"mock-{f}" for f in fields.split(",") if f != "id"}}
