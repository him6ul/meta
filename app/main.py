import asyncio
import hmac
import logging
import time
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from app import routes, webhooks
from app.audit import (AuditLog, AuditUnavailable, JournalClient, digest, new_request_id, request_context,
                       sanitize)
from app.config import get_settings
from app.graph_client import CircuitBreaker, CircuitOpenError, MetaAPIError, MetaGraphClient
from app.metrics import AUDIT_OUTCOME_UNRECORDED, AUDIT_REFUSED, HTTP_LATENCY, HTTP_REQUESTS
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


AUDIT_UNAVAILABLE_BODY = {"error": "audit trail unavailable: action refused (fail-closed)"}


def create_app(transport: httpx.AsyncBaseTransport | None = None,
               journal_transport: httpx.AsyncBaseTransport | None = None) -> FastAPI:
    settings = get_settings()
    setup_logging(settings)
    journal = (JournalClient(settings.audit_journal_url, settings.audit_journal_token,
                             timeout=settings.audit_journal_timeout_seconds, transport=journal_transport)
               if settings.audit_journal_url else None)
    audit = AuditLog(settings.audit_log_path, journal=journal)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.meta = MetaGraphClient(settings, transport=transport, audit=audit)
        # Refuse to start serving until the journal accepts records (the gateway may still be booting).
        for attempt in range(30):
            try:
                await audit.arecord("app.started", actor="system", resource="meta-api-tester",
                                    graph_url=settings.graph_url, api_key_auth=bool(settings.api_keys),
                                    audit_journal=bool(journal),
                                    token_configured=bool(settings.meta_access_token),
                                    app_secret_configured=bool(settings.meta_app_secret))
                break
            except AuditUnavailable:
                if attempt == 29:
                    raise
                log.warning("audit journal not ready; retrying startup")
                await asyncio.sleep(1)
        log.info("started", extra={"graph_url": settings.graph_url, "audit_journal": bool(journal)})
        yield
        try:
            await audit.arecord("app.stopped", actor="system", resource="meta-api-tester")
        except AuditUnavailable:
            log.error("app.stopped not durably audited")
        await app.state.meta.aclose()
        if journal:
            await journal.aclose()

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
        query = sanitize(dict(request.query_params)) or None
        status = 500
        response = None
        try:
            received_seq = None
            if audited:
                # Write-ahead gate: the request is durably recorded before any handler runs.
                try:
                    received = await audit.arecord("http.request.received", resource=path,
                                                   method=request.method, query=query, body=digest(body))
                    received_seq = received["seq"]
                except AuditUnavailable:
                    AUDIT_REFUSED.labels("http_request").inc()
                    status = 503
                    response = JSONResponse(status_code=503, content=AUDIT_UNAVAILABLE_BODY)
            if response is None:
                if not authenticated:
                    status = 401
                    response = JSONResponse(status_code=401, content={"error": "missing or invalid X-API-Key"})
                else:
                    response = await call_next(request)
                    status = response.status_code
                if audited:
                    # Durable before the client sees the response.
                    route = request.scope.get("route")
                    outcome = ("denied" if status in (401, 403) else
                               "success" if status < 400 else "failure")
                    try:
                        await audit.arecord(
                            "http.request", outcome=outcome, resource=path, method=request.method,
                            route=route.path if route is not None else "unmatched", http_status=status,
                            duration_ms=round((time.perf_counter() - start) * 1000, 1), query=query,
                            body=digest(body), received_seq=received_seq)
                    except AuditUnavailable:
                        AUDIT_OUTCOME_UNRECORDED.labels("http_request").inc()
                        response.headers["x-audit-outcome"] = "unrecorded"
            response.headers["x-request-id"] = request_id
            return response
        finally:
            elapsed = time.perf_counter() - start
            route = request.scope.get("route")
            label = route.path if route is not None else "unmatched"
            if path != "/metrics":
                HTTP_REQUESTS.labels(label, request.method, str(status)).inc()
                HTTP_LATENCY.labels(label, request.method).observe(elapsed)

    @app.exception_handler(MetaAPIError)
    async def meta_error(_: Request, exc: MetaAPIError):
        # Surface Meta's error body; map throttling to 429 and Meta 5xx to 502.
        status = 429 if exc.is_throttle else (502 if exc.status >= 500 else exc.status)
        return JSONResponse(status_code=status, content={"error": exc.as_dict()})

    @app.exception_handler(AuditUnavailable)
    async def audit_unavailable(_: Request, exc: AuditUnavailable):
        return JSONResponse(status_code=503, content=AUDIT_UNAVAILABLE_BODY)

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
        if journal:
            checks["audit_journal_reachable"] = await journal.healthy()
        ok = all(checks.values())
        return JSONResponse(status_code=200 if ok else 503, content={"ready": ok, "checks": checks})

    @app.get("/metrics", include_in_schema=False)
    async def metrics():
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    app.include_router(routes.router)
    app.include_router(webhooks.router)
    return app


app = create_app()
