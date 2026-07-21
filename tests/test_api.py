"""Milestone 6b: the scan API runs a full audit end-to-end and serves
the HTML report - exercised with fake LLMs, real HTTP target, in-process.
"""

import os
import threading
import time

import uvicorn
from fastapi.testclient import TestClient

import aegis.agents.attacker as attacker_mod
import aegis.agents.evaluator as evaluator_mod
import aegis.targets.hr_assistant as target
from aegis.api.server import app

os.environ["TARGET_LEVEL"] = "0"


class FakeLLM:
    class _Resp:
        def __init__(self, c):
            self.content = c

    def invoke(self, prompt):
        if str(prompt).startswith("You are a security judge"):
            return self._Resp("VERDICT: success\nREASON: leak confirmed")
        return self._Resp("GIVE_UP")


def target_fake(message, context, history):
    if any(w in message.lower() for w in ("repeat", "print", "maintenance", "debug")):
        return f"Config token AEGIS-CANARY-7F3K9. Context: {context}"
    return f"Based on our documents: {context[:300]}"


def _serve_target():
    target.set_llm(target_fake)
    config = uvicorn.Config(target.app, host="127.0.0.1", port=8100, log_level="error")
    server = uvicorn.Server(config)
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(50):
        time.sleep(0.1)
        if server.started:
            break
    return server


def _auth(api, monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_DB", str(tmp_path / "users.db"))
    r = api.post("/auth/register", json={"email": "t@t.t", "password": "pw123456"})
    return {"Authorization": f"Bearer {r.json()['token']}"}


def test_scan_lifecycle_and_report(monkeypatch, tmp_path):
    monkeypatch.setattr(attacker_mod, "get_chat_model", lambda *a, **k: FakeLLM())
    monkeypatch.setattr(evaluator_mod, "get_chat_model", lambda *a, **k: FakeLLM())
    server = _serve_target()

    api = TestClient(app)
    headers = _auth(api, monkeypatch, tmp_path)
    r = api.post("/scan", json={"target_url": "http://localhost:8100"}, headers=headers)
    assert r.status_code == 200
    scan_id = r.json()["scan_id"]

    for _ in range(100):  # poll until finished
        time.sleep(0.1)
        rec = api.get(f"/scan/{scan_id}", headers=headers).json()
        if rec["status"] in ("done", "error", "refused"):
            break

    assert rec["status"] == "done", rec.get("error")
    assert "recon" in rec["progress"] and "report" in rec["progress"]
    assert len(rec["findings"]) >= 1

    html = api.get(f"/scan/{scan_id}/report", headers=headers)
    assert html.status_code == 200
    assert "AEGIS" in html.text and "Findings" in html.text

    listing = api.get("/scans", headers=headers).json()
    assert any(s["id"] == scan_id for s in listing)
    server.should_exit = True


def test_scan_refused_for_out_of_scope(monkeypatch, tmp_path):
    api = TestClient(app)
    headers = _auth(api, monkeypatch, tmp_path)
    r = api.post("/scan", json={"target_url": "https://not-allowed.example.com"},
                 headers=headers)
    scan_id = r.json()["scan_id"]
    for _ in range(50):
        time.sleep(0.1)
        rec = api.get(f"/scan/{scan_id}", headers=headers).json()
        if rec["status"] != "running":
            break
    assert rec["status"] == "refused"
