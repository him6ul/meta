"""Periodic Meta access-token health check via /debug_token.

Publishes validity, expiry and scope coverage as metrics so alerts fire days before the token stops
working, instead of after calls start failing with OAuth error 190.
"""
import asyncio
import logging
import time
from typing import Any

from app.audit import AuditUnavailable
from app.config import Settings
from app.graph_client import CircuitOpenError, MetaAPIError, MetaGraphClient
from app.metrics import (
    META_TOKEN_CHECK_LAST_SUCCESS,
    META_TOKEN_CHECK_FAILURES,
    META_TOKEN_DATA_ACCESS_EXPIRES,
    META_TOKEN_EXPIRES,
    META_TOKEN_MISSING_SCOPES,
    META_TOKEN_VALID,
)

log = logging.getLogger("meta.token")


def inspector_token(settings: Settings) -> str | None:
    """debug_token needs an app token (APP_ID|APP_SECRET) or a developer token; fall back to the token itself."""
    if settings.meta_app_id and settings.meta_app_secret:
        return f"{settings.meta_app_id}|{settings.meta_app_secret}"
    return None


class TokenMonitor:
    def __init__(self, settings: Settings, client: MetaGraphClient):
        self.settings = settings
        self.client = client
        self.last: dict[str, Any] = {"checked": False}
        self._task: asyncio.Task | None = None

    @property
    def required_scopes(self) -> set[str]:
        return {s.strip() for s in self.settings.meta_required_scopes.split(",") if s.strip()}

    async def check(self) -> dict[str, Any]:
        s = self.settings
        if not s.meta_access_token:
            self.last = {"checked": False, "reason": "META_ACCESS_TOKEN not configured"}
            return self.last
        try:
            resp = await self.client.get("/debug_token", params={"input_token": s.meta_access_token},
                                         token=inspector_token(s))
        except (MetaAPIError, CircuitOpenError, AuditUnavailable, Exception) as exc:  # noqa: BLE001
            META_TOKEN_CHECK_FAILURES.inc()
            self.last = {**self.last, "error": repr(exc), "error_at": time.time()}
            log.warning("token check failed", extra={"error": repr(exc)})
            return self.last

        data = resp.get("data", {})
        scopes = set(data.get("scopes", []))
        missing = sorted(self.required_scopes - scopes)
        expires_at = int(data.get("expires_at") or 0)            # 0 = never expires
        data_access = int(data.get("data_access_expires_at") or 0)
        valid = bool(data.get("is_valid"))

        META_TOKEN_VALID.set(1 if valid else 0)
        META_TOKEN_EXPIRES.set(expires_at)
        META_TOKEN_DATA_ACCESS_EXPIRES.set(data_access)
        META_TOKEN_MISSING_SCOPES.set(len(missing))
        META_TOKEN_CHECK_LAST_SUCCESS.set(time.time())

        now = time.time()
        self.last = {
            "checked": True, "checked_at": now, "is_valid": valid, "type": data.get("type"),
            "app_id": data.get("app_id"), "expires_at": expires_at or None,
            "expires_in_days": round((expires_at - now) / 86400, 2) if expires_at else None,
            "data_access_expires_at": data_access or None,
            "data_access_expires_in_days": round((data_access - now) / 86400, 2) if data_access else None,
            "scopes": sorted(scopes), "missing_required_scopes": missing,
            "error": (data.get("error") or {}).get("message"),
        }
        log.info("token checked", extra={k: v for k, v in self.last.items() if k != "scopes"})
        return self.last

    async def _loop(self) -> None:
        while True:
            await self.check()
            await asyncio.sleep(self.settings.meta_token_check_interval_seconds)

    def start(self) -> None:
        if self.settings.meta_token_check_interval_seconds > 0:
            self._task = asyncio.create_task(self._loop(), name="meta-token-monitor")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
