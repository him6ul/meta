import os
import tempfile

import pytest

os.environ.update({
    "META_GRAPH_BASE_URL": "https://graph.test",
    "META_API_VERSION": "v24.0",
    "META_ACCESS_TOKEN": "test-token",
    "META_APP_ID": "999",
    "META_APP_SECRET": "test-secret",
    "META_WEBHOOK_VERIFY_TOKEN": "verify-me",
    "WHATSAPP_PHONE_NUMBER_ID": "1098765",
    "META_PAGE_ID": "2000001",
    "META_BACKOFF_BASE_SECONDS": "0",
    "META_MAX_RETRIES": "2",
    "META_CIRCUIT_FAILURE_THRESHOLD": "3",
    "OTEL_EXPORTER_OTLP_ENDPOINT": "",
    "META_TOKEN_CHECK_INTERVAL_SECONDS": "0",
    "AUDIT_LOG_PATH": os.path.join(tempfile.mkdtemp(), "audit.jsonl"),
})


@pytest.fixture(autouse=True)
def fresh_audit_log(tmp_path, monkeypatch, request):
    """Each test gets its own audit file so chain assertions are independent."""
    from app.config import get_settings
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("META_WEBHOOK_DEDUP_PATH", str(tmp_path / "dedup.sqlite"))
    monkeypatch.setenv("WHATSAPP_DELIVERY_DB_PATH", str(tmp_path / "deliveries.sqlite"))
    get_settings.cache_clear()
    yield tmp_path / "audit.jsonl"
    get_settings.cache_clear()
