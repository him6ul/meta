import hmac
import logging
import time
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from app import routes, webhooks
from app.audit import AuditLog, digest, new_request_id, request_context, sanitize
from app.config import get_settings
from app.graph_client import CircuitBreaker, CircuitOpenError, MetaAPIError, MetaGraphClient
from app.metrics import HTTP_LATENCY, HTTP_REQUESTS
from app.observability import setup_logging, setup_tracing

log = logging.getLogger("app")

# Probe/scrape traffic isn't a user action; everything else is audited.
UNAUDITED_PATHS = {"/metrics", "/health", "/ready"}


def resolve_actor(request: Request, api_keys: dict[str, str]) -> tuple[str | None, bool]:
    """Return (actor, authenticated). With API keys configured, /api/* requires a valid X-API-Key."""
    if api_keys:
        presented = request.headers.get("x-api-key", "")
        for key, name in api_keys.items():
            if hmac.compare_digest(presented, key):
                return name, True
        if request.url.path.startswith("/api"):
            return None, False
    claimed = request.headers.get("x-actor")
    return (f"unverified:{claimed}" if claimed else "anonymous"), True


def create_app(transport: httpx.AsyncBaseTransport | None = None) -> FastAPI:
    settings = get_settings()
    setup_logging(settings)
    audit = AuditLog(settings.audit_log_path)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.meta = MetaGraphClient(settings, transport=transport, audit=audit)
        audit.record("app.started", actor="system", resource="meta-api-tester",
                     graph_url=settings.graph_url, api_key_auth=bool(settings.api_keys),
                     token_configured=bool(settings.meta_access_token),
                     app_secret_configured=bool(settings.meta_app_secret))
        log.info("started", extra={"graph_url": settings.graph_url})
        yield
        audit.record("app.stopped", actor="system", resource="meta-api-tester")
        await app.state.meta.aclose()

    app = FastAPI(title="Meta API Tester", version="1.1.0", lifespan=lifespan,
                  description="Test harness for Meta Graph API (WhatsApp, Pages, Instagram) with "
                              "Prometheus metrics, OpenTelemetry traces, structured logs and a "
                              "hash-chained audit trail.")
    app.state.audit = audit
    setup_tracing(settings, app)

    @app.middleware("http")
    async def audit_and_metrics(request: Request, call_next):
        start = time.perf_counter()
        path = request.url.path
        audited = path not in UNAUDITED_PATHS
        request_id = request.headers.get("x-request-id") or new_request_id()
        actor, authenticated = resolve_actor(request, settings.api_keys)
        request_context.set({"request_id": request_id, "actor": actor or "unauthenticated",
                             "ip": request.client.host if request.client else None,
                             "user_agent": request.headers.get("user-agent")})
        body = await request.body() if audited and request.method in ("POST", "PUT", "PATCH", "DELETE") else b""
        status = 500
        try:
            if not authenticated:
                status = 401
                response = JSONResponse(status_code=401, content={"error": "missing or invalid X-API-Key"})
            else:
                response = await call_next(request)
                status = response.status_code
            response.headers["x-request-id"] = request_id
            return response
        finally:
            elapsed = time.perf_counter() - start
            route = request.scope.get("route")
            label = route.path if route is not None else "unmatched"
            if path != "/metrics":
                HTTP_REQUESTS.labels(label, request.method, str(status)).inc()
                HTTP_LATENCY.labels(label, request.method).observe(elapsed)
            if audited:
                outcome = ("denied" if status in (401, 403) else
                           "success" if status < 400 else "failure")
                audit.record("http.request", outcome=outcome, resource=path, method=request.method,
                             route=label, http_status=status, duration_ms=round(elapsed * 1000, 1),
                             query=sanitize(dict(request.query_params)) or None, body=digest(body))

    @app.exception_handler(MetaAPIError)
    async def meta_error(_: Request, exc: MetaAPIError):
        # Surface Meta's error body; map throttling to 429 and Meta 5xx to 502.
        status = 429 if exc.is_throttle else (502 if exc.status >= 500 else exc.status)
        return JSONResponse(status_code=status, content={"error": exc.as_dict()})

    @app.exception_handler(CircuitOpenError)
    async def circuit_open(_: Request, exc: CircuitOpenError):
        return JSONResponse(status_code=503, content={"error": str(exc)})

    @app.exception_handler(httpx.TransportError)
    async def transport_error(_: Request, exc: httpx.TransportError):
        return JSONResponse(status_code=504, content={"error": f"upstream unreachable: {exc!r}"})

    @app.get("/health", tags=["ops"])
    async def health():
        return {"status": "ok"}

    @app.get("/ready", tags=["ops"])
    async def ready(request: Request):
        meta: MetaGraphClient = request.app.state.meta
        checks = {
            "access_token_configured": bool(settings.meta_access_token),
            "circuit_closed": meta.breaker.state != CircuitBreaker.OPEN,
            "audit_log_writable": audit.writable(),
        }
        ok = all(checks.values())
        return JSONResponse(status_code=200 if ok else 503, content={"ready": ok, "checks": checks})

    @app.get("/metrics", include_in_schema=False)
    async def metrics():
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    app.include_router(routes.router)
    app.include_router(webhooks.router)
    return app


app = create_app()
