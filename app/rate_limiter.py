"""Proactive, client-side rate limiting for Meta calls, so we slow down *before* Meta throttles us.

1. Usage-based pacing from Meta's own headers (app-wide usage applies to every call; Business Use Case
   usage and regain-access windows apply only to calls in that product: WhatsApp, Pages, Instagram) (X-App-Usage, X-Business-Use-Case-Usage, X-Ad-Account-Usage):
   below SOFT% calls go straight through; between SOFT% and HARD% each call is delayed proportionally; at
   HARD% or while Meta reports `estimated_time_to_regain_access`, calls are refused locally (429 +
   Retry-After) without spending quota. Readings older than META_USAGE_STALE_SECONDS are ignored, so an old
   high reading can't lock us out: the next call goes through and refreshes it.
2. WhatsApp throughput: a token bucket per sending phone number (Cloud API default 80 msg/s).
3. WhatsApp pair limit: a token bucket per (phone number, recipient). Meta enforces a per-recipient rate
   (error 131056); tune the rate/burst to your account.

A call that would wait longer than META_RATE_MAX_WAIT_SECONDS is refused instead of queued.
"""
import asyncio
import re
import time
from collections import OrderedDict
from typing import Any

from app.config import Settings
from app.metrics import META_LOCAL_RATE_LIMITED, META_RATE_LIMIT_WAIT

_WA_MESSAGES = re.compile(r"^/?(\d+)/messages$")


def usage_category(path: str) -> str | None:
    """Which Business Use Case bucket a call draws from (BUC limits are per product, not global)."""
    p = path.rstrip("/")
    if p.endswith("/messages") or p.endswith("/message_templates"):
        return "whatsapp"
    if p.endswith("/feed") or p.endswith("/posts"):
        return "pages"
    if p.endswith("/media") or p.endswith("/media_publish"):
        return "instagram"
    return None


class LocalRateLimited(Exception):
    def __init__(self, reason: str, retry_after: float):
        super().__init__(f"locally rate limited ({reason}); retry after {retry_after:.1f}s")
        self.reason = reason
        self.retry_after = max(1.0, retry_after)


class TokenBucket:
    def __init__(self, rate: float, burst: float):
        self.rate, self.burst = rate, burst
        self.tokens, self.updated = burst, time.monotonic()

    def reserve(self) -> float:
        """Take one token; return how long the caller must wait for it (0 = now)."""
        now = time.monotonic()
        self.tokens = min(self.burst, self.tokens + (now - self.updated) * self.rate)
        self.updated = now
        self.tokens -= 1
        return 0.0 if self.tokens >= 0 else -self.tokens / self.rate

    def refund(self) -> None:
        self.tokens = min(self.burst, self.tokens + 1)


class MetaRateLimiter:
    def __init__(self, settings: Settings):
        self.s = settings
        self.usage: dict[str, tuple[float, float]] = {}   # scope -> (max pct, observed_at)
        self.regain_until: dict[str | None, float] = {}   # BUC type (None = app-wide) -> unix time
        self.phone_buckets: dict[str, TokenBucket] = {}
        self.pair_buckets: OrderedDict[tuple[str, str], TokenBucket] = OrderedDict()

    # ---------- feedback from Meta ----------
    def observe(self, parsed: dict[str, Any]) -> None:
        now = time.time()
        if app := parsed.get("app"):
            self.usage["app"] = (max(float(v) for v in app.values()), now)
        for scope_id, entries in (parsed.get("business_use_case") or {}).items():
            for e in entries:
                pct = max(float(e.get(k, 0)) for k in ("call_count", "total_cputime", "total_time"))
                utype = e.get("type")
                self.usage[f"buc:{scope_id}:{utype}"] = (pct, now)
                minutes = float(e.get("estimated_time_to_regain_access") or 0)
                if minutes > 0:
                    self.regain_until[utype] = max(self.regain_until.get(utype, 0.0), now + minutes * 60)
        if (ads := parsed.get("ad_account")) and "acc_id_util_pct" in ads:
            self.usage["ads"] = (float(ads["acc_id_util_pct"]), now)

    def current_usage(self, category: str | None = None) -> float:
        """App-wide usage always counts; BUC usage only for calls in the same product category.
        category="*" returns the max over everything (for display)."""
        cutoff = time.time() - self.s.meta_usage_stale_seconds
        fresh = [pct for scope, (pct, at) in self.usage.items() if at >= cutoff and (
            category == "*" or scope in ("app", "ads") or (category and scope.endswith(f":{category}")))]
        return max(fresh, default=0.0)

    def regain_in(self, category: str | None) -> float:
        now = time.time()
        return max(0.0, self.regain_until.get(None, 0.0) - now,
                   self.regain_until.get(category, 0.0) - now if category else 0.0)

    # ---------- gate ----------
    async def before_call(self, method: str, path: str, json_body: dict | None) -> float:
        """Wait or raise LocalRateLimited. Returns the total seconds waited."""
        category = usage_category(path)
        regain = self.regain_in(category)
        if regain > 0:
            raise self._limited("regain_access", regain)
        usage = self.current_usage(category)
        soft, hard = self.s.meta_rate_soft_pct, self.s.meta_rate_hard_pct
        if usage >= hard:
            raise self._limited("usage_hard", self.s.meta_usage_stale_seconds)
        waited = 0.0
        if usage >= soft:
            delay = self.s.meta_rate_max_delay_seconds * (usage - soft) / max(1e-9, hard - soft)
            waited += await self._wait("usage_soft", delay)

        m = _WA_MESSAGES.match(path)
        if method == "POST" and m:
            phone = m.group(1)
            bucket = self.phone_buckets.setdefault(
                phone, TokenBucket(self.s.wa_messages_per_second, self.s.wa_messages_per_second))
            waited += await self._take(bucket, "wa_throughput")
            to = (json_body or {}).get("to")
            if to and self.s.wa_pair_rate_per_second > 0:
                key = (phone, str(to))
                pair = self.pair_buckets.get(key)
                if pair is None:
                    pair = self.pair_buckets[key] = TokenBucket(self.s.wa_pair_rate_per_second, self.s.wa_pair_burst)
                    if len(self.pair_buckets) > 50_000:
                        self.pair_buckets.popitem(last=False)
                self.pair_buckets.move_to_end(key)
                try:
                    waited += await self._take(pair, "wa_pair")
                except LocalRateLimited:
                    bucket.refund()   # we never sent it: give the phone-level token back
                    raise
        return waited

    async def _take(self, bucket: TokenBucket, reason: str) -> float:
        wait = bucket.reserve()
        if wait > self.s.meta_rate_max_wait_seconds:
            bucket.refund()
            raise self._limited(reason, wait)
        return await self._wait(reason, wait)

    async def _wait(self, reason: str, seconds: float) -> float:
        if seconds <= 0:
            return 0.0
        META_RATE_LIMIT_WAIT.labels(reason).observe(seconds)
        await asyncio.sleep(seconds)
        return seconds

    @staticmethod
    def _limited(reason: str, retry_after: float) -> LocalRateLimited:
        META_LOCAL_RATE_LIMITED.labels(reason).inc()
        return LocalRateLimited(reason, retry_after)
