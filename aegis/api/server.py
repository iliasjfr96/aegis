"""Aegis scan API - powers the React dashboard.

POST /scan {target_url}        -> launch an audit (background thread)
GET  /scans                    -> list all scans
GET  /scan/{id}                -> status, live progress, findings
GET  /scan/{id}/report         -> the generated HTML report
POST /compare {base_url, ports} -> run one scan per defense level, side by side
"""

import threading
import time
import uuid

from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from aegis.auth import users
from aegis.auth import targets as user_targets
from aegis.auth.context import SCAN_LLM
from aegis import store

app = FastAPI(title="Aegis API")

# Single-process deployment: the 3 vulnerable demo targets are mounted
# alongside the API at /t0 /t1 /t2 (defense levels 0/1/2)
from aegis.targets.hr_assistant import create_app as _target_app

for _lvl in (0, 1, 2):
    app.mount(f"/t{_lvl}", _target_app(_lvl))

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

_bearer = HTTPBearer(auto_error=False)


def current_user(creds: HTTPAuthorizationCredentials | None = Security(_bearer)) -> str:
    if creds is None:
        raise HTTPException(401, "missing bearer token")
    try:
        return users.verify_token(creds.credentials)
    except Exception:
        raise HTTPException(401, "invalid or expired token")


class ScanRequest(BaseModel):
    target_url: str
    provider: str | None = None  # use one of YOUR saved keys for this scan


class RegisterRequest(BaseModel):
    email: str
    password: str


class ProviderKeyRequest(BaseModel):
    provider: str  # "kimi" | "openai" | "anthropic" | "ollama"
    api_key: str
    model: str = ""


class TargetRequest(BaseModel):
    url: str


class CompareRequest(BaseModel):
    urls: list[str]  # e.g. level 0/1/2 target URLs


class WebScanRequest(BaseModel):
    target_url: str
    jwt_token: str | None = None
    ws_url: str | None = None  # e.g. ws://localhost:5174/ws for realtime apps


def _initial_state(target_url: str, owner: str | None = None) -> dict:
    return {
        "messages": [],
        "target_url": target_url,
        "owner": owner,
        "profile": None,
        "planned_techniques": [],
        "attempts": [],
        "findings": [],
        "requests_used": 0,
        "status": "init",
        "report_path": "",
    }


def _run_scan(scan_id: str, target_url: str, llm_override: dict | None = None) -> None:
    from aegis.graph.build import build_graph

    rec = store.get(scan_id)
    SCAN_LLM.set(llm_override)  # per-scan BYOK: user's own provider key
    try:
        graph = build_graph()
        for event in graph.stream(_initial_state(target_url, rec.get("owner")),
                                  stream_mode="updates"):
            node = next(iter(event))
            rec["progress"].append(node)
            rec["current_node"] = node
            state_update = event[node]
            if "status" in state_update:
                rec["status"] = state_update["status"]
            if "attempts" in state_update:
                rec["attempts"] = [a.model_dump() for a in state_update["attempts"]]
            if "findings" in state_update:
                rec["findings"] = [f.model_dump() for f in state_update["findings"]]
            if "report_path" in state_update:
                rec["report_path"] = state_update["report_path"]
            if state_update.get("status") == "refused":
                rec["status"] = "refused"
                store.save(rec)
                return
            store.save(rec)  # live progress -> dashboard timeline
        rec["status"] = "done"
    except Exception as e:  # surface errors to the dashboard
        rec["status"] = "error"
        rec["error"] = str(e)
    finally:
        rec["finished_at"] = time.time()
        store.save(rec)


# ---------- Auth ----------
@app.post("/auth/register")
def register(req: RegisterRequest):
    try:
        return {"token": users.register(req.email, req.password)}
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.post("/auth/login")
def login(req: RegisterRequest):
    try:
        return {"token": users.login(req.email, req.password)}
    except ValueError as e:
        raise HTTPException(401, str(e))


# ---------- BYOK provider keys ----------
@app.put("/me/provider")
def save_key(req: ProviderKeyRequest, email: str = Depends(current_user)):
    users.save_provider_key(email, req.provider, req.api_key, req.model)
    return {"saved": req.provider}


@app.get("/me/providers")
def my_providers(email: str = Depends(current_user)):
    return users.list_providers(email)


# ---------- Verified targets (audit your own sites) ----------
@app.post("/me/targets")
def add_target(req: TargetRequest, email: str = Depends(current_user)):
    """Register a target; returns the token to serve at /.well-known/aegis-verify.txt"""
    return user_targets.register_target(email, req.url)


@app.get("/me/targets")
def my_targets(email: str = Depends(current_user)):
    return user_targets.list_targets(email)


@app.post("/me/targets/verify")
def verify_target(req: TargetRequest, email: str = Depends(current_user)):
    result = user_targets.verify_target(email, req.url)
    if not result["verified"]:
        raise HTTPException(400, result.get("error", "verification failed"))
    return result


# ---------- Scans ----------
@app.post("/scan")
def launch_scan(req: ScanRequest, email: str = Depends(current_user)):
    override = None
    if req.provider:
        saved = users.get_provider_key(email, req.provider)
        if not saved:
            raise HTTPException(400, f"no key saved for provider '{req.provider}'")
        override = {"provider": req.provider, "api_key": saved["api_key"],
                    "model": saved["model"]}
    scan_id = str(uuid.uuid4())[:8]
    store.create(scan_id, email, "llm", req.target_url)
    threading.Thread(target=_run_scan, args=(scan_id, req.target_url, override),
                     daemon=True).start()
    return {"scan_id": scan_id}


@app.get("/scans")
def list_scans(email: str = Depends(current_user)):
    return store.list_for(email)


@app.get("/scan/{scan_id}")
def get_scan(scan_id: str, email: str = Depends(current_user)):
    rec = store.get(scan_id)
    if not rec or rec.get("owner") != email:
        raise HTTPException(404, "scan not found")
    return rec


@app.get("/scan/{scan_id}/report", response_class=HTMLResponse)
def get_report(scan_id: str, email: str = Depends(current_user)):
    rec = store.get(scan_id)
    if not rec or rec.get("owner") != email or not rec.get("report_path"):
        raise HTTPException(404, "report not ready")
    from pathlib import Path

    return Path(rec["report_path"]).read_text(encoding="utf-8")


def _run_webscan(scan_id: str, req: WebScanRequest) -> None:
    from aegis.report.generator import generate_report
    from aegis.websec import scanner, ws_scanner

    rec = store.get(scan_id)
    try:
        findings = scanner.run_webscan(req.target_url, req.jwt_token,
                                       owner=rec.get("owner"))
        rec["progress"].append("web_checks")
        if req.ws_url:
            findings += ws_scanner.run_ws_scan(req.ws_url, owner=rec.get("owner"))
            rec["progress"].append("ws_checks")
        rec["findings"] = [f.model_dump() for f in findings]
        path = generate_report(req.target_url, None, findings,
                               attempts_count=len(findings), requests_used=len(findings))
        rec["report_path"] = str(path)
        rec["status"] = "done"
        rec["current_node"] = "report"
        rec["progress"].append("report")
    except scanner.TargetUnreachableError as e:
        rec["status"] = "error"
        rec["error"] = f"target unreachable - scan aborted: {e}"
    except Exception as e:
        rec["status"] = "error"
        rec["error"] = str(e)
    finally:
        rec["finished_at"] = time.time()
        store.save(rec)


@app.post("/webscan")
def launch_webscan(req: WebScanRequest, email: str = Depends(current_user)):
    """Deterministic web/WebSocket audit - no LLM, no quota consumed."""
    scan_id = str(uuid.uuid4())[:8]
    store.create(scan_id, email, "websec", req.target_url)
    rec = store.get(scan_id)
    rec["current_node"] = "web_checks"
    store.save(rec)
    threading.Thread(target=_run_webscan, args=(scan_id, req), daemon=True).start()
    return {"scan_id": scan_id}


@app.post("/compare")
def compare_levels(req: CompareRequest, email: str = Depends(current_user)):
    """Launch one scan per URL (e.g. defense level 0/1/2) and return their ids."""
    ids = [launch_scan(ScanRequest(target_url=u), email)["scan_id"] for u in req.urls]
    return {"scan_ids": ids}


# --- Single-process deployment: serve the React dashboard from FastAPI ---
from pathlib import Path as _Path

from fastapi.responses import FileResponse as _FileResponse
from fastapi.staticfiles import StaticFiles as _StaticFiles

_STATIC = _Path("static")
if _STATIC.is_dir():
    app.mount("/assets", _StaticFiles(directory=_STATIC / "assets"), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str):
        """SPA fallback: any non-API GET serves the dashboard."""
        candidate = _STATIC / full_path
        if full_path and candidate.is_file():
            return _FileResponse(candidate)
        return _FileResponse(_STATIC / "index.html")
