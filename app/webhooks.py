"""Meta webhook endpoint: subscription verification (GET) and signed event delivery (POST)."""
import hashlib
import hmac
import logging
from collections import deque

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse

from app.config import get_settings
from app.metrics import WEBHOOK_EVENTS, WEBHOOK_VERIFICATIONS

log = logging.getLogger("meta.webhooks")
router = APIRouter(prefix="/webhooks", tags=["webhooks"])

# Last N deliveries, for inspection via GET /webhooks/meta/recent while testing.
RECENT_EVENTS: deque = deque(maxlen=50)


def verify_signature(app_secret: str, body: bytes, header: str | None) -> bool:
    if not header or not header.startswith("sha256="):
        return False
    expected = hmac.new(app_secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header.removeprefix("sha256="))


@router.get("/meta", response_class=PlainTextResponse)
async def verify(
    mode: str = Query("", alias="hub.mode"),
    token: str = Query("", alias="hub.verify_token"),
    challenge: str = Query("", alias="hub.challenge"),
):
    settings = get_settings()
    if mode == "subscribe" and hmac.compare_digest(token, settings.meta_webhook_verify_token):
        WEBHOOK_VERIFICATIONS.labels("ok").inc()
        log.info("webhook verified")
        return challenge
    WEBHOOK_VERIFICATIONS.labels("rejected").inc()
    log.warning("webhook verification rejected", extra={"mode": mode})
    raise HTTPException(status_code=403, detail="verification failed")


@router.post("/meta")
async def receive(request: Request):
    settings = get_settings()
    body = await request.body()
    signature = request.headers.get("x-hub-signature-256")

    if settings.meta_app_secret:
        sig_state = "valid" if verify_signature(settings.meta_app_secret, body, signature) else "invalid"
    else:
        sig_state = "unchecked"

    try:
        payload = await request.json()
    except ValueError:
        WEBHOOK_EVENTS.labels("unknown", "unknown", sig_state).inc()
        raise HTTPException(status_code=400, detail="invalid JSON")

    obj = payload.get("object", "unknown")
    if sig_state == "invalid":
        WEBHOOK_EVENTS.labels(obj, "n/a", sig_state).inc()
        log.warning("webhook signature invalid", extra={"object": obj})
        raise HTTPException(status_code=401, detail="invalid signature")

    for entry in payload.get("entry", []):
        # WhatsApp/Pages/Instagram use "changes"; Messenger uses "messaging".
        fields = [c.get("field", "unknown") for c in entry.get("changes", [])]
        if entry.get("messaging"):
            fields.append("messaging")
        for field in fields or ["unknown"]:
            WEBHOOK_EVENTS.labels(obj, field, sig_state).inc()

    RECENT_EVENTS.appendleft({"signature": sig_state, "payload": payload})
    log.info("webhook received", extra={"object": obj, "entries": len(payload.get("entry", [])),
                                        "signature": sig_state})
    # Meta expects a fast 200; do heavy processing asynchronously in a real system.
    return {"status": "received"}


@router.get("/meta/recent")
async def recent():
    return list(RECENT_EVENTS)
