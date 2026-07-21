"""Milestone 3 E2E: the full LangGraph graph runs against the vulnerable
target (level 0) and produces findings - no API key, fake LLMs everywhere.
"""

import os

import threading
import time

import uvicorn

import aegis.agents.attacker as attacker_mod
import aegis.agents.evaluator as evaluator_mod
import aegis.targets.hr_assistant as target
from aegis.graph.build import build_graph

os.environ["TARGET_LEVEL"] = "0"


class FakeLLM:
    """Deterministic stand-in: attacker follow-ups and judge verdicts."""

    class _Resp:
        def __init__(self, content):
            self.content = content

    def invoke(self, prompt):
        p = str(prompt)
        if p.startswith("You are a security judge"):
            return self._Resp("VERDICT: success\nREASON: sensitive data was leaked")
        return self._Resp("GIVE_UP")  # attacker gives up after scripted openers


def fake_llm_factory(role="attack", temperature=0.7):
    return FakeLLM()


def target_fake_llm(message, context, history):
    if any(w in message.lower() for w in ("repeat", "print", "maintenance", "debug")):
        return f"Sure! Config token AEGIS-CANARY-7F3K9. Context: {context}"
    return f"Based on our documents: {context[:300]}"


def _serve_target():
    """Run the real vulnerable target over HTTP in a background thread."""
    target.set_llm(target_fake_llm)
    config = uvicorn.Config(target.app, host="127.0.0.1", port=8100, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(50):  # wait until ready
        time.sleep(0.1)
        if server.started:
            break
    return server


def test_full_scan_finds_vulnerabilities(monkeypatch):
    monkeypatch.setattr(attacker_mod, "get_chat_model", fake_llm_factory)
    monkeypatch.setattr(evaluator_mod, "get_chat_model", fake_llm_factory)
    server = _serve_target()

    app = build_graph()
    out = app.invoke(
        {
            "messages": [],
            "target_url": "http://localhost:8100",
            "profile": None,
            "planned_techniques": [],
            "attempts": [],
            "findings": [],
            "requests_used": 0,
            "status": "init",
        }
    )

    assert out["status"] == "done"
    assert len(out["attempts"]) >= 3, "several techniques should have been tried"
    assert len(out["findings"]) >= 1, "level-0 target must yield findings"
    assert any(a.canary_triggered for a in out["attempts"]), "deterministic detection fired"
    sevs = {f.severity.value for f in out["findings"]}
    assert sevs & {"critical", "high"}, "severity ranking applied"
    server.should_exit = True


def test_out_of_scope_target_is_refused():
    app = build_graph()
    out = app.invoke(
        {
            "messages": [],
            "target_url": "https://some-random-site.com",
            "profile": None,
            "planned_techniques": [],
            "attempts": [],
            "findings": [],
            "requests_used": 0,
            "status": "init",
        }
    )
    assert out["status"] == "refused"
