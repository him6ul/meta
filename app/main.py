import logging
import time
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from app import routes, webhooks
from app.config import get_settings
from app.graph_client import CircuitBreaker, CircuitOpenError, MetaAPIError, MetaGraphClient
from app.metrics import HTTP_LATENCY, HTTP_REQUESTS
from app.observability import setup_logging, setup_tracing

log = logging.getLogger("app")


def create_app(transport: httpx.AsyncBaseTransport | None = None) -> FastAPI:
    settings = get_settings()
    setup_logging(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.meta = MetaGraphClient(settings, transport=transport)
        log.info("started", extra={"graph_url": settings.graph_url,
                                   "token_configured": bool(settings.meta_access_token),
                                   "app_secret_configured": bool(settings.meta_app_secret)})
        yield
        await app.state.meta.aclose()

    app = FastAPI(title="Meta API Tester", version="1.0.0", lifespan=lifespan,
                  description="Test harness for Meta Graph API (WhatsApp, Pages, Instagram) with "
                              "Prometheus metrics, OpenTelemetry traces and structured logs.")
    setup_tracing(settings, app)

    @app.middleware("http")
    async def metrics_middleware(request: Request, call_next):
        start = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            return response
        finally:
            route = request.scope.get("route")
            label = route.path if route is not None else "unmatched"
            if label != "/metrics":
                HTTP_REQUESTS.labels(label, request.method, str(status)).inc()
                HTTP_LATENCY.labels(label, request.method).observe(time.perf_counter() - start)

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
