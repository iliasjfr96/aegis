"""Web security module: deterministic findings against a deliberately
bad app, JWT offline checks, and WebSocket probes against a live server."""

import asyncio
import json
import threading

import pytest
import uvicorn
import websockets
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from aegis.config import get_settings
from aegis.websec import scanner, ws_scanner

bad_app = FastAPI()
bad_app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                       allow_methods=["*"], allow_headers=["*"])


@bad_app.get("/")
def root():
    from fastapi.responses import JSONResponse
    r = JSONResponse({"ok": True})
    r.set_cookie("session", "abc")  # no flags
    r.headers["server"] = "nginx/1.18.0"
    return r


@bad_app.get("/.env")
def env_file():
    return "DB_PASSWORD=hunter2"


async def _ws_handler(ws):
    async for msg in ws:
        await ws.send(json.dumps({"echo": msg}))


@pytest.fixture(scope="module")
def servers(monkeypatch_module=None):
    # HTTP bad app on 8105
    cfg = uvicorn.Config(bad_app, host="127.0.0.1", port=8105, log_level="error")
    srv = uvicorn.Server(cfg)
    threading.Thread(target=srv.run, daemon=True).start()

    # naive WS echo server on 8106 (no auth, no rate limit)
    loop = asyncio.new_event_loop()

    def run_ws():
        asyncio.set_event_loop(loop)
        async def main():
            async with websockets.serve(_ws_handler, "127.0.0.1", 8106):
                await asyncio.Future()
        loop.run_until_complete(main())

    threading.Thread(target=run_ws, daemon=True).start()
    import time
    time.sleep(1.5)
    yield
    srv.should_exit = True


def test_web_findings(servers, monkeypatch):
    monkeypatch.setattr(get_settings(), "target_whitelist",
                        "http://localhost:8105,ws://localhost:8106")
    findings = scanner.run_webscan("http://localhost:8105")
    cats = {f.owasp.value for f in findings}
    assert "WEB-HEADERS" in cats
    assert "WEB-CORS" in cats          # wildcard + credentials
    assert "WEB-EXPOSED" in cats       # /.env served
    assert "WEB-COOKIES" in cats       # cookie without flags
    exposed = [f for f in findings if f.owasp.value == "WEB-EXPOSED"]
    assert exposed[0].severity.value == "critical"


def test_jwt_offline_checks():
    import base64
    import hashlib
    import hmac
    import json as j

    pad = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    header = pad(j.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = pad(j.dumps({"sub": "user1"}).encode())  # no exp
    sig = pad(hmac.new(b"secret", f"{header}.{payload}".encode(), hashlib.sha256).digest())
    token = f"{header}.{payload}.{sig}"

    findings = scanner.check_jwt(token)
    titles = " ".join(f.title for f in findings)
    assert "no expiry" in titles
    assert "weak secret" in titles
    assert any(f.severity.value == "critical" for f in findings)


def test_ws_findings(servers, monkeypatch):
    monkeypatch.setattr(get_settings(), "target_whitelist",
                        "http://localhost:8105,ws://localhost:8106")
    findings = ws_scanner.run_ws_scan("ws://localhost:8106", flood_n=20)
    cats = {f.owasp.value for f in findings}
    assert "WS-AUTH" in cats       # echo server answers anyone
    assert "WS-RATELIMIT" in cats  # accepts whole flood
