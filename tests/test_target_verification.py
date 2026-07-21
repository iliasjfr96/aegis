"""Target ownership verification: register -> token -> verify -> scannable."""

import os

import pytest
from fastapi.testclient import TestClient

os.environ["AEGIS_DB"] = "/tmp/aegis_test_targets.db"
os.environ["AEGIS_SECRET_KEY"] = "test-secret"

from aegis.api.server import app  # noqa: E402
from aegis.auth import targets, users  # noqa: E402
from aegis.auth.scope import is_allowed  # noqa: E402


@pytest.fixture(autouse=True)
def clean():
    os.environ["AEGIS_DB"] = "/tmp/aegis_test_targets.db"
    if os.path.exists("/tmp/aegis_test_targets.db"):
        os.remove("/tmp/aegis_test_targets.db")
    yield


def test_register_and_verify_flow():
    users.register("owner@x.y", "pw123456")
    rec = targets.register_target("owner@x.y", "https://mon-site.fr")
    assert not rec["verified"]
    assert rec["token"].startswith("aegis-verify-")

    # token served on the site -> verification succeeds
    ok = targets.verify_target("owner@x.y", "https://mon-site.fr",
                               fetcher=lambda u: f"hello {rec['token']} world")
    assert ok["verified"]
    assert is_allowed("https://mon-site.fr", "owner@x.y")
    assert is_allowed("https://mon-site.fr/api/chat", "owner@x.y")


def test_verify_fails_without_token_file():
    users.register("o2@x.y", "pw123456")
    targets.register_target("o2@x.y", "https://autre-site.fr")
    bad = targets.verify_target("o2@x.y", "https://autre-site.fr", fetcher=lambda u: "nope")
    assert not bad["verified"]
    assert not is_allowed("https://autre-site.fr", "o2@x.y")


def test_verified_target_is_per_user():
    users.register("o3@x.y", "pw123456")
    rec = targets.register_target("o3@x.y", "https://site-o3.fr")
    targets.verify_target("o3@x.y", "https://site-o3.fr", fetcher=lambda u: rec["token"])
    assert not is_allowed("https://site-o3.fr", "someone-else@x.y"), "per-user scope"


def test_api_endpoints():
    api = TestClient(app)
    tok = api.post("/auth/register",
                   json={"email": "api@x.y", "password": "pw123456"}).json()["token"]
    h = {"Authorization": f"Bearer {tok}"}
    r = api.post("/me/targets", json={"url": "https://mon-app.fr"}, headers=h)
    assert r.status_code == 200 and "token" in r.json()
    r = api.get("/me/targets", headers=h)
    assert r.json()[0]["url"] == "https://mon-app.fr"
