"""Zero-AI mode: full audit with no LLM anywhere - simulated target model,
scripted attacks, heuristic judge. Proves the pipeline runs standalone."""

import os
import threading
import time

import pytest
import uvicorn

os.environ["TARGET_LEVEL"] = "0"
os.environ["TARGET_SIMULATED_LLM"] = "1"

import aegis.targets.hr_assistant as target  # noqa: E402
from aegis.config import get_settings  # noqa: E402
from aegis.graph.build import build_graph  # noqa: E402


@pytest.fixture(scope="module")
def target_server():
    # Other test modules reload/patch the target module; re-import it clean
    # with the zero-AI env vars so the served app is level 0 + simulated LLM.
    import importlib

    os.environ["TARGET_LEVEL"] = "0"
    os.environ["TARGET_SIMULATED_LLM"] = "1"
    importlib.reload(target)
    config = uvicorn.Config(target.app, host="127.0.0.1", port=8103, log_level="error")
    server = uvicorn.Server(config)
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(50):
        time.sleep(0.1)
        if server.started:
            break
    yield server
    server.should_exit = True


def _scan(url, monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "scripted_mode", True)
    monkeypatch.setattr(s, "target_whitelist", "http://localhost:8103")
    app = build_graph()
    return app.invoke(
        {
            "messages": [],
            "target_url": url,
            "profile": None,
            "planned_techniques": [],
            "attempts": [],
            "findings": [],
            "requests_used": 0,
            "status": "init",
            "report_path": "",
        }
    )


def test_zero_ai_full_audit_finds_vulns(target_server, monkeypatch):
    out = _scan("http://localhost:8103", monkeypatch)
    assert out["status"] == "done"
    assert len(out["findings"]) >= 2, "scripted attacks + heuristic judge still confirm vulns"
    assert any(a.canary_triggered for a in out["attempts"])
    assert out["report_path"].endswith(".html")


def test_zero_ai_report_file_exists(target_server, monkeypatch):
    from pathlib import Path

    out = _scan("http://localhost:8103", monkeypatch)
    html = Path(out["report_path"]).read_text()
    assert "CRITICAL" in html or "HIGH" in html
