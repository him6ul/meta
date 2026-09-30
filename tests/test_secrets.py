import json

import boto3
import pytest
import respx
from fastapi.testclient import TestClient
from moto import mock_aws

from app.audit_gateway import GatewaySettings, create_gateway
from app.config import get_settings
from app.main import create_app
from app.secrets import APP_SECRET_FIELDS, SecretsError, SecretsLoader

GRAPH = "https://graph.test/v24.0"


@pytest.fixture
def sm(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    with mock_aws():
        client = boto3.client("secretsmanager", region_name="us-east-1")
        client.create_secret(Name="meta/app", SecretString=json.dumps(
            {"META_ACCESS_TOKEN": "from-secrets-manager", "META_APP_SECRET": "sm-app-secret",
             "UNRELATED": "ignored"}))
        yield client


@respx.mock
def test_app_uses_secret_values_and_audits_without_leaking(sm, monkeypatch, fresh_audit_log):
    monkeypatch.setenv("SECRETS_MANAGER_SECRET_ID", "meta/app")
    monkeypatch.setenv("SECRETS_REFRESH_SECONDS", "0")
    get_settings.cache_clear()
    route = respx.get(f"{GRAPH}/me").respond(200, json={"id": "1"})
    with TestClient(create_app(secrets_client=sm)) as c:
        c.get("/api/me")
    assert route.calls[0].request.url.params["access_token"] == "from-secrets-manager"
    raw = fresh_audit_log.read_text()
    assert "secrets.loaded" in raw and "from-secrets-manager" not in raw and "sm-app-secret" not in raw


def test_rotation_applies_in_place_and_reports_changed_fields_only(sm):
    settings = get_settings().model_copy()
    seen = []
    loader = SecretsLoader(settings, "meta/app", APP_SECRET_FIELDS, client=sm, on_change=seen.append)
    first = loader.load()
    assert set(first) == {"meta_access_token", "meta_app_secret"}
    assert loader.load() == {}                                       # no change, no event
    sm.put_secret_value(SecretId="meta/app", SecretString=json.dumps(
        {"META_ACCESS_TOKEN": "rotated", "META_APP_SECRET": "sm-app-secret"}))
    changed = loader.load()
    assert list(changed) == ["meta_access_token"] and settings.meta_access_token == "rotated"
    assert "rotated" not in json.dumps(seen)                         # fingerprints only


def test_missing_secret_fails_loudly(sm):
    with pytest.raises(SecretsError):
        SecretsLoader(get_settings().model_copy(), "does/not/exist", APP_SECRET_FIELDS, client=sm).load()


def test_gateway_accepts_previous_token_during_rotation(tmp_path):
    import uuid
    with mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket="rot", ObjectLockEnabledForBucket=True)
        settings = GatewaySettings(audit_s3_bucket="rot", audit_journal_token="new", audit_journal_token_previous="old",
                                   audit_s3_retention_days=1, audit_gateway_state_dir=str(tmp_path / "gw"))
        app = create_gateway(settings, s3=s3)
        c = TestClient(app)

        def d():
            return {"action": "x", "draft_id": uuid.uuid4().hex}
        assert c.post("/v2/records", json=d(), headers={"authorization": "Bearer old"}).status_code == 201
        assert c.post("/v2/records", json=d(), headers={"authorization": "Bearer new"}).status_code == 201
        settings.audit_journal_token_previous = ""                   # rotation finished
        assert c.post("/v2/records", json=d(), headers={"authorization": "Bearer old"}).status_code == 401
        app.state.sequencer.stop()
