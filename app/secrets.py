"""Load secrets from AWS Secrets Manager into a settings object, and refresh them for rotation.

The secret is a JSON object whose keys are settings field names (either case), e.g.
  {"META_ACCESS_TOKEN": "...", "META_APP_SECRET": "...", "AUDIT_JOURNAL_TOKEN": "...", "APP_API_KEYS": "..."}
Only fields in the caller's allow-list are applied. Values are never logged or audited: only the
names of fields that changed, plus a short fingerprint so rotations can be correlated.

Rotation without downtime: settings are mutated in place, and components read them per call (Graph
client, webhook signature check, API-key auth); the journal client gets an explicit token update. The
journal gateway accepts AUDIT_JOURNAL_TOKEN *and* AUDIT_JOURNAL_TOKEN_PREVIOUS, so rotate by moving the
old value to _PREVIOUS, setting the new one, waiting one refresh interval, then clearing _PREVIOUS.
"""
import hashlib
import json
import logging
import time
from typing import Any, Callable

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from prometheus_client import Counter, Gauge

log = logging.getLogger("secrets")

SECRETS_LAST_REFRESH = Gauge("secrets_last_refresh_timestamp_seconds", "Last successful secrets refresh")
SECRETS_REFRESH_FAILURES = Counter("secrets_refresh_failures_total", "Failed secrets refreshes")
SECRETS_ROTATIONS = Counter("secrets_rotations_total", "Secret fields whose value changed on refresh", ["field"])

APP_SECRET_FIELDS = {"meta_access_token", "meta_app_secret", "meta_webhook_verify_token", "app_api_keys",
                     "audit_journal_token"}
SHIPPER_SECRET_FIELDS = {"audit_journal_token", "audit_journal_token_previous"}


class SecretsError(RuntimeError):
    pass


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:8] if value else "empty"


class SecretsLoader:
    def __init__(self, settings: Any, secret_id: str, fields: set[str], *, region: str = "us-east-1",
                 endpoint_url: str = "", client=None,
                 on_change: Callable[[dict[str, str]], None] | None = None):
        self.settings = settings
        self.secret_id = secret_id
        self.fields = fields
        self.on_change = on_change
        self.client = client or boto3.client("secretsmanager", region_name=region,
                                             endpoint_url=endpoint_url or None)
        self.version_id: str | None = None

    def load(self) -> dict[str, str]:
        """Fetch and apply. Returns {field: new_fingerprint} for fields that changed. Raises SecretsError."""
        try:
            resp = self.client.get_secret_value(SecretId=self.secret_id)
            data = json.loads(resp["SecretString"])
        except (ClientError, BotoCoreError, KeyError, ValueError) as exc:
            SECRETS_REFRESH_FAILURES.inc()
            raise SecretsError(f"could not load secret {self.secret_id}: {type(exc).__name__}") from exc

        changed: dict[str, str] = {}
        for raw_key, value in data.items():
            field = raw_key.lower()
            if field not in self.fields or not isinstance(value, str):
                continue
            if getattr(self.settings, field, None) != value:
                setattr(self.settings, field, value)
                changed[field] = fingerprint(value)
                SECRETS_ROTATIONS.labels(field).inc()
        self.version_id = resp.get("VersionId")
        SECRETS_LAST_REFRESH.set(time.time())
        if changed:
            log.info("secrets applied", extra={"fields": sorted(changed), "version_id": self.version_id})
            if self.on_change:
                self.on_change(changed)
        return changed
