"""Meta webhook endpoint: subscription verification (GET) and signed event delivery (POST)."""
import hashlib
import hmac
import logging
from collections import deque

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse

from app.audit import digest
from app.config import get_settings
from app.metrics import ALERT_NOTIFICATIONS, WEBHOOK_EVENTS, WEBHOOK_VERIFICATIONS

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
    request: Request,
    mode: str = Query("", alias="hub.mode"),
    token: str = Query("", alias="hub.verify_token"),
    challenge: str = Query("", alias="hub.challenge"),
):
    settings = get_settings()
    if mode == "subscribe" and hmac.compare_digest(token, settings.meta_webhook_verify_token):
        WEBHOOK_VERIFICATIONS.labels("ok").inc()
        request.app.state.audit.record("webhook.meta.verify", actor="meta", resource="/webhooks/meta",
                                       mode=mode)
        log.info("webhook verified")
        return challenge
    WEBHOOK_VERIFICATIONS.labels("rejected").inc()
    request.app.state.audit.record("webhook.meta.verify", outcome="denied", actor="unknown",
                                   resource="/webhooks/meta", mode=mode, reason="verify_token mismatch")
    log.warning("webhook verification rejected", extra={"mode": mode})
    raise HTTPException(status_code=403, detail="verification failed")


@router.post("/meta")
async def receive(request: Request):
    settings = get_settings()
    audit = request.app.state.audit
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
        audit.record("webhook.meta.received", outcome="failure", actor="unknown",
                     resource="/webhooks/meta", signature=sig_state, body=digest(body), reason="invalid JSON")
        raise HTTPException(status_code=400, detail="invalid JSON")

    obj = payload.get("object", "unknown")
    if sig_state == "invalid":
        WEBHOOK_EVENTS.labels(obj, "n/a", sig_state).inc()
        log.warning("webhook signature invalid", extra={"object": obj})
        audit.record("webhook.meta.received", outcome="denied", actor="unknown",
                     resource="/webhooks/meta", object=obj, signature=sig_state, body=digest(body),
                     reason="X-Hub-Signature-256 mismatch")
        raise HTTPException(status_code=401, detail="invalid signature")

    all_fields: list[str] = []
    for entry in payload.get("entry", []):
        # WhatsApp/Pages/Instagram use "changes"; Messenger uses "messaging".
        fields = [c.get("field", "unknown") for c in entry.get("changes", [])]
        if entry.get("messaging"):
            fields.append("messaging")
        for field in fields or ["unknown"]:
            WEBHOOK_EVENTS.labels(obj, field, sig_state).inc()
        all_fields += fields
    audit.record("webhook.meta.received", actor="meta" if sig_state == "valid" else "unverified:meta",
                 resource="/webhooks/meta", object=obj, fields=sorted(set(all_fields)) or None,
                 entry_ids=[e.get("id") for e in payload.get("entry", [])], signature=sig_state,
                 body=digest(body))

    RECENT_EVENTS.appendleft({"signature": sig_state, "payload": payload})
    log.info("webhook received", extra={"object": obj, "entries": len(payload.get("entry", [])),
                                        "signature": sig_state})
    # Meta expects a fast 200; do heavy processing asynchronously in a real system.
    return {"status": "received"}


@router.get("/meta/recent")
async def recent():
    return list(RECENT_EVENTS)


@router.post("/alertmanager")
async def alertmanager(request: Request):
    """Alertmanager webhook receiver: records every notification sent (e.g. to Slack) in the audit trail."""
    payload = await request.json()
    audit = request.app.state.audit
    for alert in payload.get("alerts", []):
        labels = alert.get("labels", {})
        name, severity = labels.get("alertname", "unknown"), labels.get("severity", "none")
        ALERT_NOTIFICATIONS.labels(name, alert.get("status", "unknown"), severity).inc()
        audit.record("alert.notification", actor="alertmanager", resource=name,
                     status=alert.get("status"), severity=severity, receiver=payload.get("receiver"),
                     fingerprint=alert.get("fingerprint"), starts_at=alert.get("startsAt"),
                     ends_at=alert.get("endsAt"), summary=alert.get("annotations", {}).get("summary"),
                     group_key=payload.get("groupKey"))
    return {"status": "recorded", "alerts": len(payload.get("alerts", []))}
