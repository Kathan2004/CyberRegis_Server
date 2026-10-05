import importlib

import pytest


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("API_TOKEN", "test-token")
    monkeypatch.chdir(tmp_path)
    import config
    importlib.reload(config)
    import KALE
    importlib.reload(KALE)
    return KALE.create_app().test_client()


def test_health_is_public(client):
    assert client.get("/api/health").status_code == 200


def test_api_requires_token(client):
    assert client.get("/api/scan-history").status_code == 401


def test_wrong_token_rejected(client):
    r = client.get("/api/scan-history", headers={"Authorization": "Bearer nope"})
    assert r.status_code == 401


def test_bearer_token_accepted(client):
    r = client.get("/api/scan-history", headers={"Authorization": "Bearer test-token"})
    assert r.status_code != 401


def test_x_api_key_accepted(client):
    r = client.get("/api/scan-history", headers={"X-API-Key": "test-token"})
    assert r.status_code != 401


def test_security_headers(client):
    r = client.get("/api/health")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"


def test_production_without_token_refuses(monkeypatch):
    monkeypatch.setenv("FLASK_ENV", "production")
    monkeypatch.delenv("API_TOKEN", raising=False)
    import config
    importlib.reload(config)
    import KALE
    with pytest.raises(RuntimeError):
        importlib.reload(KALE)
