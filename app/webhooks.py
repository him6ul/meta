"""Meta webhook endpoint: subscription verification (GET) and signed event delivery (POST)."""
import hashlib
import hmac
import json
import logging
from collections import deque

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse

from app.audit import AuditUnavailable, digest
from app.config import get_settings
from app.metrics import (ALERT_NOTIFICATIONS, AUDIT_REFUSED, WEBHOOK_DUPLICATES, WEBHOOK_EVENTS,
                         WEBHOOK_REJECTED, WEBHOOK_VERIFICATIONS)
from app.webhook_dedup import event_keys

log = logging.getLogger("meta.webhooks")
router = APIRouter(prefix="/webhooks", tags=["webhooks"])

# Last N deliveries, for inspection via GET /webhooks/meta/recent while testing.
RECENT_EVENTS: deque = deque(maxlen=50)


async def durable(request: Request, action: str, **kw) -> None:
    """Record synchronously; if that fails answer 503 so Meta / Alertmanager redeliver later."""
    try:
        await request.app.state.audit.arecord(action, **kw)
    except AuditUnavailable:
        AUDIT_REFUSED.labels("webhook").inc()
        raise HTTPException(status_code=503, detail="audit trail unavailable; retry delivery")


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
        await durable(request, "webhook.meta.verify", actor="meta", resource="/webhooks/meta", mode=mode)
        log.info("webhook verified")
        return challenge
    WEBHOOK_VERIFICATIONS.labels("rejected").inc()
    await durable(request, "webhook.meta.verify", outcome="denied", actor="unknown",
                  resource="/webhooks/meta", mode=mode, reason="verify_token mismatch")
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

    if sig_state == "unchecked" and settings.meta_webhook_require_signature:
        # Misconfiguration, not a bad sender: 503 so Meta keeps retrying until META_APP_SECRET is set,
        # instead of us accepting unauthenticated events.
        WEBHOOK_REJECTED.labels("signature_missing_secret").inc()
        log.error("webhook rejected: META_APP_SECRET not configured but signatures are required")
        await durable(request, "webhook.meta.received", outcome="denied", actor="unknown",
                      resource="/webhooks/meta", signature=sig_state, body=digest(body),
                      reason="META_APP_SECRET not configured")
        raise HTTPException(status_code=503, detail="webhook signature verification not configured")

    try:
        payload = json.loads(body)
    except ValueError:
        WEBHOOK_REJECTED.labels("invalid_json").inc()
        WEBHOOK_EVENTS.labels("unknown", "unknown", sig_state).inc()
        await durable(request, "webhook.meta.received", outcome="failure", actor="unknown",
                      resource="/webhooks/meta", signature=sig_state, body=digest(body), reason="invalid JSON")
        raise HTTPException(status_code=400, detail="invalid JSON")

    obj = payload.get("object", "unknown")
    if sig_state == "invalid":
        WEBHOOK_REJECTED.labels("signature_invalid").inc()
        WEBHOOK_EVENTS.labels(obj, "n/a", sig_state).inc()
        log.warning("webhook signature invalid", extra={"object": obj})
        await durable(request, "webhook.meta.received", outcome="denied", actor="unknown",
                      resource="/webhooks/meta", object=obj, signature=sig_state, body=digest(body),
                      reason="X-Hub-Signature-256 mismatch")
        raise HTTPException(status_code=401, detail="invalid signature")

    events = event_keys(payload)
    dedup = request.app.state.webhook_dedup
    already = dedup.seen([e["key"] for e in events])
    new = [e for e in events if e["key"] not in already]
    for e in events:
        WEBHOOK_EVENTS.labels(obj, e["field"], sig_state).inc()
    for e in events:
        if e["key"] in already:
            WEBHOOK_DUPLICATES.labels(obj, e["kind"]).inc()

    # Acknowledge (200) only once the delivery is durably recorded; otherwise Meta retries.
    await durable(request, "webhook.meta.received",
                  actor="meta" if sig_state == "valid" else "unverified:meta",
                  resource="/webhooks/meta", object=obj,
                  fields=sorted({e["field"] for e in events}) or None,
                  entry_ids=[e.get("id") for e in payload.get("entry", [])], signature=sig_state,
                  events=len(events), new_event_keys=[e["key"] for e in new][:50] or None,
                  duplicate_event_keys=sorted(already)[:50] or None, body=digest(body))

    if new:
        # Process only events not seen before, then mark them. If processing raises, nothing is
        # marked and the 500 makes Meta redeliver.
        await process_events(request, payload, new)
        dedup.mark([e["key"] for e in new])

    RECENT_EVENTS.appendleft({"signature": sig_state, "new_events": [e["key"] for e in new],
                              "duplicates": sorted(already), "payload": payload})
    log.info("webhook received", extra={"object": obj, "events": len(events), "new": len(new),
                                        "duplicates": len(already), "signature": sig_state})
    return {"status": "received", "events": len(events), "new": len(new), "duplicates": len(already)}


async def process_events(request: Request, payload: dict, events: list[dict]) -> None:
    """Business handling for first-time events. Extend here; keep it idempotent where possible."""
    tracker = getattr(request.app.state, "delivery_tracker", None)
    if tracker is not None:
        await tracker.on_webhook(payload, {e["key"] for e in events})


@router.get("/meta/recent")
async def recent():
    return list(RECENT_EVENTS)


@router.post("/alertmanager")
async def alertmanager(request: Request):
    """Alertmanager webhook receiver: records every notification sent (e.g. to Slack) in the audit trail."""
    payload = await request.json()
    for alert in payload.get("alerts", []):
        labels = alert.get("labels", {})
        name, severity = labels.get("alertname", "unknown"), labels.get("severity", "none")
        await durable(request, "alert.notification", actor="alertmanager", resource=name,
                     status=alert.get("status"), severity=severity, receiver=payload.get("receiver"),
                     fingerprint=alert.get("fingerprint"), starts_at=alert.get("startsAt"),
                     ends_at=alert.get("endsAt"), summary=alert.get("annotations", {}).get("summary"),
                     group_key=payload.get("groupKey"))
        ALERT_NOTIFICATIONS.labels(name, alert.get("status", "unknown"), severity).inc()
    return {"status": "recorded", "alerts": len(payload.get("alerts", []))}
