import os

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
})
