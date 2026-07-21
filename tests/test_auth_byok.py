"""Auth + BYOK: registration, JWT, encrypted key storage, per-user isolation,
and per-scan LLM override resolution."""

import os

import pytest
from fastapi.testclient import TestClient

os.environ["AEGIS_DB"] = "/tmp/aegis_test_users.db"
os.environ["AEGIS_SECRET_KEY"] = "test-secret"

from aegis.api.server import app  # noqa: E402
from aegis.auth import users  # noqa: E402
from aegis.auth.context import SCAN_LLM  # noqa: E402
from aegis.llm import get_chat_model  # noqa: E402


@pytest.fixture(autouse=True)
def clean_db():
    os.environ["AEGIS_DB"] = "/tmp/aegis_test_users.db"  # per-test: env is shared across modules
    if os.path.exists("/tmp/aegis_test_users.db"):
        os.remove("/tmp/aegis_test_users.db")
    yield


def test_register_login_and_jwt():
    api = TestClient(app)
    r = api.post("/auth/register", json={"email": "a@b.c", "password": "pw123456"})
    assert r.status_code == 200 and r.json()["token"]
    r = api.post("/auth/login", json={"email": "a@b.c", "password": "wrong"})
    assert r.status_code == 401


def test_provider_key_encrypted_at_rest():
    users.register("sec@x.y", "pw123456")
    users.save_provider_key("sec@x.y", "kimi", "sk-kimi-secret", "k3")
    raw = open("/tmp/aegis_test_users.db", "rb").read()
    assert b"sk-kimi-secret" not in raw, "key must not be stored in plaintext"
    assert users.get_provider_key("sec@x.y", "kimi")["api_key"] == "sk-kimi-secret"


def test_scan_requires_auth():
    api = TestClient(app)
    r = api.post("/scan", json={"target_url": "http://localhost:8100"})
    assert r.status_code in (401, 403)


def test_user_isolation():
    api = TestClient(app)
    t1 = api.post("/auth/register", json={"email": "u1@x.y", "password": "pw123456"}).json()["token"]
    t2 = api.post("/auth/register", json={"email": "u2@x.y", "password": "pw123456"}).json()["token"]
    api.put("/me/provider", json={"provider": "kimi", "api_key": "sk-1", "model": "k3"},
            headers={"Authorization": f"Bearer {t1}"})
    mine = api.get("/me/providers", headers={"Authorization": f"Bearer {t2}"})
    assert mine.json() == [], "user 2 must not see user 1's keys"


def test_byok_override_flows_into_factory(monkeypatch):
    SCAN_LLM.set({"provider": "kimi", "api_key": "sk-user-own", "model": "k3"})
    try:
        llm = get_chat_model("attack")
        assert llm.model_name == "k3"
        assert llm.openai_api_key.get_secret_value() == "sk-user-own"
    finally:
        SCAN_LLM.set(None)
