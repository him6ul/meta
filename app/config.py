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
    audit_log_path: str = "data/audit.jsonl"
    app_api_keys: str = ""

    log_level: str = "INFO"
    otel_exporter_otlp_endpoint: str = ""
    otel_service_name: str = "meta-api-tester"

    @property
    def api_keys(self) -> dict[str, str]:
        """key -> actor name"""
        pairs = (p.split(":", 1) for p in self.app_api_keys.split(",") if ":" in p)
        return {key.strip(): name.strip() for name, key in pairs}

    @property
    def graph_url(self) -> str:
        return f"{self.meta_graph_base_url.rstrip('/')}/{self.meta_api_version}"


@lru_cache
def get_settings() -> Settings:
    return Settings()
