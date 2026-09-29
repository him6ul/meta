"""Test-harness endpoints that exercise common Meta Graph API products."""
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


@router.get("/rate-limits")
async def rate_limits(request: Request):
    """Last rate-limit usage headers seen from Meta, plus circuit breaker state."""
    c = client(request)
    return {"usage": c.last_usage, "circuit_state": c.breaker.state, "consecutive_failures": c.breaker.failures}


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


@router.post("/whatsapp/messages", tags=["whatsapp"])
async def whatsapp_send_text(request: Request, body: WhatsAppText):
    phone_id = require(get_settings().whatsapp_phone_number_id, "WHATSAPP_PHONE_NUMBER_ID")
    return await client(request).post(f"/{phone_id}/messages", json_body={
        "messaging_product": "whatsapp", "recipient_type": "individual", "to": body.to,
        "type": "text", "text": {"preview_url": False, "body": body.text},
    })


@router.post("/whatsapp/templates", tags=["whatsapp"])
async def whatsapp_send_template(request: Request, body: WhatsAppTemplate):
    phone_id = require(get_settings().whatsapp_phone_number_id, "WHATSAPP_PHONE_NUMBER_ID")
    template: dict[str, Any] = {"name": body.template, "language": {"code": body.language}}
    if body.components:
        template["components"] = body.components
    return await client(request).post(f"/{phone_id}/messages", json_body={
        "messaging_product": "whatsapp", "to": body.to, "type": "template", "template": template,
    })


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
                      outcome: str | None = None):
    """Newest-first audit records. `action` matches exactly or as a prefix (e.g. `meta.api`)."""
    return request.app.state.audit.query(limit=min(limit, 1000), action=action, actor=actor,
                                         request_id=request_id, outcome=outcome)


@router.get("/audit/verify", tags=["audit"])
async def audit_verify(request: Request):
    """Recompute the hash chain; `ok: false` means records were altered, removed or reordered."""
    return request.app.state.audit.verify()
