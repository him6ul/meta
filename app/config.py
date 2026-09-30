from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    meta_graph_base_url: str = "https://graph.facebook.com"
    meta_api_version: str = "v24.0"
    meta_access_token: str = ""
    meta_app_id: str = ""
    meta_app_secret: str = ""
    meta_webhook_verify_token: str = "change-me"

    whatsapp_phone_number_id: str = ""
    meta_page_id: str = ""
    instagram_account_id: str = ""

    meta_timeout_seconds: float = 15.0
    meta_max_retries: int = Field(3, ge=0, le=10)
    meta_backoff_base_seconds: float = 0.5
    meta_backoff_max_seconds: float = 20.0
    meta_circuit_failure_threshold: int = 5
    meta_circuit_reset_seconds: float = 30.0

    # Audit trail. APP_API_KEYS="alice:key1,ci-bot:key2" enables API-key auth on /api/*; the key's
    # name becomes the audited actor. Unset = open access, actor taken from X-Actor (unverified).
    audit_log_path: str = "data/audit.jsonl"   # "{replica}" is replaced by the replica id
    app_replica_id: str = ""                   # default: container hostname
    app_api_keys: str = ""
    # Audit gateway (global sequencer + S3 Object Lock). Unset = local single-writer mode (dev only).
    audit_journal_url: str = ""
    audit_journal_token: str = ""
    audit_journal_timeout_seconds: float = 2.0

    # AWS Secrets Manager (optional). Fields in the secret override env; refreshed for rotation.
    secrets_manager_secret_id: str = ""
    secrets_manager_region: str = "us-east-1"
    secrets_manager_endpoint_url: str = ""
    secrets_refresh_seconds: float = 300

    # Proactive rate limiting (see app/rate_limiter.py)
    meta_rate_limiting_enabled: bool = True
    meta_rate_soft_pct: float = 80
    meta_rate_hard_pct: float = 95
    meta_rate_max_delay_seconds: float = 2.0
    meta_rate_max_wait_seconds: float = 2.0
    meta_usage_stale_seconds: float = 120
    wa_messages_per_second: float = 80
    wa_pair_rate_per_second: float = 1 / 6   # 0 disables the per-recipient limit
    wa_pair_burst: float = 10

    # Token health: /debug_token every N seconds (0 = off); alert if these scopes are missing.
    meta_token_check_interval_seconds: float = 3600
    meta_required_scopes: str = ""

    # Webhooks: reject unsigned deliveries (503, so Meta retries once the secret is configured).
    meta_webhook_require_signature: bool = True
    meta_webhook_dedup_path: str = "data/webhook_dedup.sqlite"
    meta_webhook_dedup_ttl_days: float = 7

    # WhatsApp delivery tracking
    whatsapp_delivery_db_path: str = "data/deliveries.sqlite"
    whatsapp_stale_after_seconds: float = 600

    log_level: str = "INFO"
    otel_exporter_otlp_endpoint: str = ""
    otel_service_name: str = "meta-api-tester"

    @property
    def api_keys(self) -> dict[str, str]:
        """key -> actor name"""
        pairs = (p.split(":", 1) for p in self.app_api_keys.split(",") if ":" in p)
        return {key.strip(): name.strip() for name, key in pairs}

    @property
    def replica_id(self) -> str:
        import socket
        return self.app_replica_id or socket.gethostname()

    @property
    def graph_url(self) -> str:
        return f"{self.meta_graph_base_url.rstrip('/')}/{self.meta_api_version}"


@lru_cache
def get_settings() -> Settings:
    return Settings()
