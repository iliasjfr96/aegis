"""Generic adapter: audits an app with a totally different API shape."""

import threading
import time

import pytest
import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel

from aegis.config import get_settings
from aegis.targets.generic import GenericTargetClient, TargetRefusedError

# A fake "ReadPlay-like" app: /api/chat, field "prompt", reply nested
fake_app = FastAPI()


class In(BaseModel):
    prompt: str


@fake_app.post("/api/chat")
def chat(inp: In):
    return {"data": {"answer": f"echo: {inp.prompt}"}}


@pytest.fixture(scope="module")
def fake_server():
    config = uvicorn.Config(fake_app, host="127.0.0.1", port=8104, log_level="error")
    server = uvicorn.Server(config)
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(50):
        time.sleep(0.1)
        if server.started:
            break
    yield server
    server.should_exit = True


def test_custom_paths_fields_and_headers(fake_server, monkeypatch):
    monkeypatch.setenv("AEGIS_TARGET_CHAT_PATH", "/api/chat")
    monkeypatch.setenv("AEGIS_TARGET_REQUEST_FIELD", "prompt")
    monkeypatch.setenv("AEGIS_TARGET_RESPONSE_FIELD", "data.answer")
    monkeypatch.setenv("AEGIS_TARGET_HEALTH_PATH", "")
    monkeypatch.setenv("AEGIS_TARGET_HEADERS", "Authorization:Bearer test-token")
    monkeypatch.setattr(
        get_settings(), "target_whitelist", "http://localhost:8104"
    )

    c = GenericTargetClient("http://localhost:8104")
    assert c.chat("hello") == "echo: hello"
    assert c._client.headers["authorization"] == "Bearer test-token"
    assert c.health()["status"] == "skipped"


def test_out_of_scope_still_refused():
    with pytest.raises(TargetRefusedError):
        GenericTargetClient("https://someone-elses-site.com")
