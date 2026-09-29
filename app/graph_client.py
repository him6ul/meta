"""Instrumented async client for the Meta Graph API.

Handles: appsecret_proof, Graph error parsing, retry with exponential backoff + jitter on transient
errors / throttling, rate-limit header tracking (X-App-Usage, X-Business-Use-Case-Usage,
X-Ad-Account-Usage), and a simple consecutive-failure circuit breaker.
"""
import asyncio
import hashlib
import hmac
import json
import logging
import random
import time
from dataclasses import dataclass
from typing import Any

import httpx
from opentelemetry import trace

from app.config import Settings
from app.metrics import (
    META_ATTEMPTS,
    META_CIRCUIT_REJECTIONS,
    META_CIRCUIT_STATE,
    META_ERRORS,
    META_LATENCY,
    META_RATE_LIMIT,
    META_REGAIN_ACCESS,
    META_REQUESTS,
    META_RETRIES,
    normalize_endpoint,
)

log = logging.getLogger("meta.client")
tracer = trace.get_tracer("meta.client")

# Graph error codes that indicate throttling or a temporary server-side problem.
# https://developers.facebook.com/docs/graph-api/guides/error-handling
THROTTLE_CODES = {4, 17, 32, 341, 613, 80001, 80002, 80003, 80004, 80005, 80006, 80008, 80009,
                  80014, 130429, 131056}
TRANSIENT_CODES = {1, 2} | THROTTLE_CODES
RETRYABLE_HTTP = {429, 500, 502, 503, 504}


@dataclass
class MetaAPIError(Exception):
    status: int
    message: str
    code: int | None = None
    subcode: int | None = None
    type: str | None = None
    fbtrace_id: str | None = None
    is_transient: bool = False

    def __str__(self) -> str:
        return f"Meta API error {self.status} code={self.code} subcode={self.subcode}: {self.message}"

    @property
    def is_throttle(self) -> bool:
        return self.code in THROTTLE_CODES or self.status == 429

    @property
    def retryable(self) -> bool:
        return self.is_transient or self.code in TRANSIENT_CODES or self.status in RETRYABLE_HTTP

    def as_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None}

    @classmethod
    def from_response(cls, resp: httpx.Response) -> "MetaAPIError":
        try:
            err = resp.json().get("error", {})
        except (ValueError, AttributeError):
            err = {}
        return cls(
            status=resp.status_code,
            message=err.get("message") or resp.text[:300] or resp.reason_phrase,
            code=err.get("code"),
            subcode=err.get("error_subcode"),
            type=err.get("type"),
            fbtrace_id=err.get("fbtrace_id"),
            is_transient=bool(err.get("is_transient", False)),
        )


class CircuitOpenError(Exception):
    pass


class CircuitBreaker:
    CLOSED, HALF_OPEN, OPEN = 0, 1, 2

    def __init__(self, failure_threshold: int, reset_seconds: float):
        self.failure_threshold = failure_threshold
        self.reset_seconds = reset_seconds
        self.failures = 0
        self.opened_at = 0.0
        self.state = self.CLOSED
        META_CIRCUIT_STATE.set(self.state)

    def _set(self, state: int) -> None:
        if state != self.state:
            log.warning("circuit state change", extra={"from_state": self.state, "to_state": state})
        self.state = state
        META_CIRCUIT_STATE.set(state)

    def before_call(self) -> None:
        if self.state == self.OPEN:
            if time.monotonic() - self.opened_at >= self.reset_seconds:
                self._set(self.HALF_OPEN)
            else:
                META_CIRCUIT_REJECTIONS.inc()
                raise CircuitOpenError("Meta API circuit is open; failing fast")

    def record_success(self) -> None:
        self.failures = 0
        self._set(self.CLOSED)

    def record_failure(self) -> None:
        self.failures += 1
        if self.state == self.HALF_OPEN or self.failures >= self.failure_threshold:
            self.opened_at = time.monotonic()
            self._set(self.OPEN)


def record_rate_limit_headers(headers: httpx.Headers) -> dict[str, Any]:
    """Parse Meta usage headers into gauges. Returns the parsed values (useful for logging/debug)."""
    parsed: dict[str, Any] = {}
    if raw := headers.get("x-app-usage"):
        try:
            usage = json.loads(raw)
            parsed["app"] = usage
            for metric, value in usage.items():
                META_RATE_LIMIT.labels("x-app-usage", "app", "app", metric).set(float(value))
        except (ValueError, TypeError):
            log.debug("unparseable x-app-usage", extra={"raw": raw})
    if raw := headers.get("x-business-use-case-usage"):
        try:
            usage = json.loads(raw)
            parsed["business_use_case"] = usage
            for scope_id, entries in usage.items():
                for entry in entries:
                    utype = entry.get("type", "unknown")
                    for metric in ("call_count", "total_cputime", "total_time"):
                        if metric in entry:
                            META_RATE_LIMIT.labels("x-business-use-case-usage", scope_id, utype,
                                                   metric).set(float(entry[metric]))
                    META_REGAIN_ACCESS.labels(scope_id, utype).set(
                        float(entry.get("estimated_time_to_regain_access", 0)))
        except (ValueError, TypeError, AttributeError):
            log.debug("unparseable x-business-use-case-usage", extra={"raw": raw})
    if raw := headers.get("x-ad-account-usage"):
        try:
            usage = json.loads(raw)
            parsed["ad_account"] = usage
            if "acc_id_util_pct" in usage:
                META_RATE_LIMIT.labels("x-ad-account-usage", "ad_account", "ads",
                                       "acc_id_util_pct").set(float(usage["acc_id_util_pct"]))
        except (ValueError, TypeError):
            log.debug("unparseable x-ad-account-usage", extra={"raw": raw})
    return parsed


class MetaGraphClient:
    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None):
        self.settings = settings
        self.breaker = CircuitBreaker(settings.meta_circuit_failure_threshold,
                                      settings.meta_circuit_reset_seconds)
        self._http = httpx.AsyncClient(
            base_url=settings.graph_url,
            timeout=settings.meta_timeout_seconds,
            transport=transport,
            headers={"User-Agent": "meta-api-tester/1.0"},
        )
        self.last_usage: dict[str, Any] = {}

    async def aclose(self) -> None:
        await self._http.aclose()

    def appsecret_proof(self, token: str) -> str:
        return hmac.new(self.settings.meta_app_secret.encode(), token.encode(), hashlib.sha256).hexdigest()

    def _auth_params(self, token: str | None) -> dict[str, str]:
        token = token or self.settings.meta_access_token
        if not token:
            return {}
        params = {"access_token": token}
        if self.settings.meta_app_secret:
            params["appsecret_proof"] = self.appsecret_proof(token)
        return params

    def _backoff(self, attempt: int, err: MetaAPIError | None) -> float:
        delay = min(self.settings.meta_backoff_max_seconds,
                    self.settings.meta_backoff_base_seconds * (2 ** attempt))
        if err is not None and err.is_throttle:
            delay = min(self.settings.meta_backoff_max_seconds, delay * 2)
        return delay * random.uniform(0.5, 1.0)

    async def request(self, method: str, path: str, *, params: dict | None = None,
                      json_body: dict | None = None, token: str | None = None) -> dict[str, Any]:
        endpoint = normalize_endpoint(path)
        query = {**(params or {}), **self._auth_params(token)}
        last_status = "error"

        with tracer.start_as_current_span(f"meta {method} {endpoint}") as span:
            span.set_attribute("meta.endpoint", endpoint)
            try:
                self.breaker.before_call()
            except CircuitOpenError:
                META_REQUESTS.labels(endpoint, method, "none", "circuit_open").inc()
                span.set_attribute("meta.outcome", "circuit_open")
                raise

            for attempt in range(self.settings.meta_max_retries + 1):
                err: MetaAPIError | None = None
                start = time.perf_counter()
                try:
                    resp = await self._http.request(method, path, params=query, json=json_body)
                except (httpx.TimeoutException, httpx.TransportError) as exc:
                    elapsed = time.perf_counter() - start
                    META_LATENCY.labels(endpoint, method).observe(elapsed)
                    reason = "timeout" if isinstance(exc, httpx.TimeoutException) else "network"
                    META_ATTEMPTS.labels(endpoint, method, reason).inc()
                    last_status = reason
                    log.warning("meta call failed", extra={"endpoint": endpoint, "method": method,
                                                           "attempt": attempt, "error": repr(exc)})
                    if attempt < self.settings.meta_max_retries:
                        META_RETRIES.labels(endpoint, reason).inc()
                        await asyncio.sleep(self._backoff(attempt, None))
                        continue
                    self.breaker.record_failure()
                    META_REQUESTS.labels(endpoint, method, reason, "failure").inc()
                    span.set_status(trace.StatusCode.ERROR, reason)
                    raise

                elapsed = time.perf_counter() - start
                status = str(resp.status_code)
                last_status = status
                META_LATENCY.labels(endpoint, method).observe(elapsed)
                META_ATTEMPTS.labels(endpoint, method, status).inc()
                self.last_usage = record_rate_limit_headers(resp.headers) or self.last_usage
                span.set_attribute("http.status_code", resp.status_code)
                span.set_attribute("meta.attempt", attempt)

                if resp.is_success:
                    self.breaker.record_success()
                    META_REQUESTS.labels(endpoint, method, status, "success").inc()
                    log.info("meta call ok", extra={"endpoint": endpoint, "method": method,
                                                    "status": resp.status_code, "attempt": attempt,
                                                    "duration_ms": round(elapsed * 1000, 1)})
                    return resp.json() if resp.content else {}

                err = MetaAPIError.from_response(resp)
                META_ERRORS.labels(endpoint, str(err.code), str(err.subcode), str(err.type)).inc()
                span.set_attribute("meta.error_code", str(err.code))
                if err.fbtrace_id:
                    span.set_attribute("meta.fbtrace_id", err.fbtrace_id)
                log.warning("meta call error", extra={"endpoint": endpoint, "method": method,
                                                      "attempt": attempt,
                                                      **{f"meta_{k}": v for k, v in err.as_dict().items()}})

                if err.retryable and attempt < self.settings.meta_max_retries:
                    META_RETRIES.labels(endpoint, "throttled" if err.is_throttle else "transient").inc()
                    await asyncio.sleep(self._backoff(attempt, err))
                    continue

                # Client errors (bad params, expired token, permissions) are the caller's fault and
                # should not trip the breaker; server errors and exhausted throttling should.
                if err.retryable:
                    self.breaker.record_failure()
                else:
                    self.breaker.record_success()
                outcome = "throttled" if err.is_throttle else "failure"
                META_REQUESTS.labels(endpoint, method, status, outcome).inc()
                span.set_status(trace.StatusCode.ERROR, str(err))
                raise err

        raise RuntimeError(f"unreachable (last_status={last_status})")

    async def get(self, path: str, **kw) -> dict[str, Any]:
        return await self.request("GET", path, **kw)

    async def post(self, path: str, **kw) -> dict[str, Any]:
        return await self.request("POST", path, **kw)

    async def delete(self, path: str, **kw) -> dict[str, Any]:
        return await self.request("DELETE", path, **kw)
