"""Test-harness endpoints that exercise common Meta Graph API products."""
import hashlib
import time
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from app.config import get_settings

router = APIRouter(prefix="/api", tags=["meta"])


def client(request: Request):
    return request.app.state.meta


def require(value: str, name: str) -> str:
    if not value:
        raise HTTPException(status_code=400, detail=f"{name} is not configured")
    return value


# ---------- Core / auth ----------
@router.get("/me")
async def me(request: Request, fields: str = "id,name"):
    return await client(request).get("/me", params={"fields": fields})


@router.get("/debug-token")
async def debug_token(request: Request):
    """Inspect the configured token (validity, scopes, expiry). Uses an app token as the inspector."""
    s = get_settings()
    require(s.meta_access_token, "META_ACCESS_TOKEN")
    app_token = f"{s.meta_app_id}|{s.meta_app_secret}" if s.meta_app_id and s.meta_app_secret else None
    return await client(request).get("/debug_token", params={"input_token": s.meta_access_token},
                                     token=app_token)


@router.get("/token-status")
async def token_status(request: Request, refresh: bool = False):
    """Result of the periodic /debug_token check (expiry, validity, missing scopes)."""
    monitor = request.app.state.token_monitor
    return await monitor.check() if refresh or not monitor.last.get("checked") else monitor.last


@router.get("/rate-limits")
async def rate_limits(request: Request):
    """Last rate-limit usage headers seen from Meta, plus circuit breaker state."""
    c = client(request)
    limiter = c.limiter
    return {"usage": c.last_usage, "circuit_state": c.breaker.state, "consecutive_failures": c.breaker.failures,
            "pacing": None if limiter is None else {
                "max_usage_pct": limiter.current_usage("*"),
                "regain_access_in_s": {str(k or "app"): round(v - time.time(), 1)
                                       for k, v in limiter.regain_until.items() if v > time.time()},
                "tracked_phone_numbers": len(limiter.phone_buckets),
                "tracked_recipient_pairs": len(limiter.pair_buckets)}}


@router.get("/graph/{path:path}")
async def graph_get(request: Request, path: str):
    """Generic GET passthrough, e.g. /api/graph/{page-id}?fields=name,followers_count"""
    params = dict(request.query_params)
    return await client(request).get("/" + path, params=params)


# ---------- WhatsApp Cloud API ----------
class WhatsAppText(BaseModel):
    to: str = Field(..., description="Recipient phone number in E.164 without '+', e.g. 15551234567")
    text: str


class WhatsAppTemplate(BaseModel):
    to: str
    template: str = "hello_world"
    language: str = "en_US"
    components: list[dict[str, Any]] = []


def track_sent(request: Request, result: dict, kind: str, to: str) -> dict:
    for m in result.get("messages", []):
        if m.get("id"):
            request.app.state.delivery_tracker.on_sent(
                m["id"], kind, recipient_hash=hashlib.sha256(to.encode()).hexdigest()[:16])
    return result


@router.post("/whatsapp/messages", tags=["whatsapp"])
async def whatsapp_send_text(request: Request, body: WhatsAppText):
    phone_id = require(get_settings().whatsapp_phone_number_id, "WHATSAPP_PHONE_NUMBER_ID")
    result = await client(request).post(f"/{phone_id}/messages", json_body={
        "messaging_product": "whatsapp", "recipient_type": "individual", "to": body.to,
        "type": "text", "text": {"preview_url": False, "body": body.text},
    })
    return track_sent(request, result, "text", body.to)


@router.post("/whatsapp/templates", tags=["whatsapp"])
async def whatsapp_send_template(request: Request, body: WhatsAppTemplate):
    phone_id = require(get_settings().whatsapp_phone_number_id, "WHATSAPP_PHONE_NUMBER_ID")
    template: dict[str, Any] = {"name": body.template, "language": {"code": body.language}}
    if body.components:
        template["components"] = body.components
    result = await client(request).post(f"/{phone_id}/messages", json_body={
        "messaging_product": "whatsapp", "to": body.to, "type": "template", "template": template,
    })
    return track_sent(request, result, "template", body.to)


@router.get("/whatsapp/messages/{wamid}/status", tags=["whatsapp"])
async def whatsapp_message_status(request: Request, wamid: str):
    row = request.app.state.delivery_tracker.get(wamid)
    if row is None:
        raise HTTPException(status_code=404, detail="unknown message id")
    return row


@router.get("/whatsapp/delivery-stats", tags=["whatsapp"])
async def whatsapp_delivery_stats(request: Request, window_seconds: float = 3600):
    return request.app.state.delivery_tracker.stats(window_seconds)


# ---------- Facebook Pages ----------
class PagePost(BaseModel):
    message: str
    link: str | None = None


@router.get("/pages/posts", tags=["pages"])
async def page_posts(request: Request, limit: int = 10):
    page_id = require(get_settings().meta_page_id, "META_PAGE_ID")
    return await client(request).get(f"/{page_id}/posts",
                                     params={"limit": limit, "fields": "id,message,created_time"})


@router.post("/pages/posts", tags=["pages"])
async def page_publish(request: Request, body: PagePost):
    page_id = require(get_settings().meta_page_id, "META_PAGE_ID")
    return await client(request).post(f"/{page_id}/feed", params=body.model_dump(exclude_none=True))


# ---------- Instagram ----------
@router.get("/instagram/media", tags=["instagram"])
async def instagram_media(request: Request, limit: int = 10):
    ig_id = require(get_settings().instagram_account_id, "INSTAGRAM_ACCOUNT_ID")
    return await client(request).get(f"/{ig_id}/media",
                                     params={"limit": limit, "fields": "id,caption,media_type,timestamp"})


# ---------- Audit trail ----------
@router.get("/audit", tags=["audit"])
async def audit_query(request: Request, limit: int = 100, action: str | None = None,
                      actor: str | None = None, request_id: str | None = None,
                      outcome: str | None = None, replica: str | None = None):
    """Newest-first audit records. `action` matches exactly or as a prefix (e.g. `meta.api`).
    Gateway mode: the global chain across ALL replicas (from the gateway index)."""
    audit = request.app.state.audit
    if audit.gateway is not None:
        return await audit.gateway.query(limit=min(limit, 1000), action=action, actor=actor,
                                         request_id=request_id, outcome=outcome, replica=replica)
    return audit.query(limit=min(limit, 1000), action=action, actor=actor, request_id=request_id, outcome=outcome)


@router.get("/audit/verify", tags=["audit"])
async def audit_verify(request: Request):
    """Local mode: recompute the local hash chain. Gateway mode: the latest archive verification plus a
    check of this replica's cache against the authoritative chain."""
    audit = request.app.state.audit
    if audit.gateway is None:
        return audit.verify()
    last = await audit.gateway.last_verification()
    cache = await audit.cache_consistency()
    archive = None if last is None else {k: last.get(k) for k in ("ok", "verified_at", "head_seq", "blocks", "findings", "open_intent_count")}
    ok = (archive is None or archive["ok"]) and not cache["mismatched_seqs"] and not cache["unknown_to_gateway"]
    return {"ok": ok, "mode": "gateway", "replica": audit.replica, "archive": archive, "replica_cache": cache}
