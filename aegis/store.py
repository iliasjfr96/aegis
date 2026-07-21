"""Scan persistence: SQLite-backed store (survives restarts, enables
audit history per user and posture tracking over time).
"""

import json
import os
import sqlite3
import threading
import time

_LOCAL = threading.local()


def _db_path() -> str:
    return os.environ.get("AEGIS_SCANS_DB", "aegis_scans.db")


def _conn() -> sqlite3.Connection:
    if not getattr(_LOCAL, "conn", None):
        _LOCAL.conn = sqlite3.connect(_db_path(), check_same_thread=False)
        _LOCAL.conn.execute(
            """CREATE TABLE IF NOT EXISTS scans(
               id TEXT PRIMARY KEY, owner TEXT, kind TEXT, target_url TEXT,
               status TEXT, current_node TEXT, progress TEXT, attempts TEXT,
               findings TEXT, report_path TEXT, error TEXT,
               started_at REAL, finished_at REAL)"""
        )
    return _LOCAL.conn


def create(scan_id: str, owner: str, kind: str, target_url: str) -> dict:
    rec = {
        "id": scan_id, "owner": owner, "kind": kind, "target_url": target_url,
        "status": "running", "current_node": "scope_guard", "progress": [],
        "attempts": [], "findings": [], "report_path": "", "error": None,
        "started_at": time.time(), "finished_at": None,
    }
    save(rec)
    return rec


def save(rec: dict) -> None:
    _conn().execute(
        "INSERT OR REPLACE INTO scans VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (rec["id"], rec["owner"], rec.get("kind", "llm"), rec["target_url"],
         rec["status"], rec.get("current_node", ""), json.dumps(rec.get("progress", [])),
         json.dumps([a if isinstance(a, dict) else a.model_dump() for a in rec.get("attempts", [])]),
         json.dumps([f if isinstance(f, dict) else f.model_dump() for f in rec.get("findings", [])]),
         rec.get("report_path", ""), rec.get("error"),
         rec["started_at"], rec.get("finished_at")),
    )
    _conn().commit()


def get(scan_id: str) -> dict | None:
    row = _conn().execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    return _to_dict(row) if row else None


def list_for(owner: str) -> list[dict]:
    rows = _conn().execute(
        "SELECT * FROM scans WHERE owner=? ORDER BY started_at DESC", (owner,)
    ).fetchall()
    return [_to_dict(r) for r in rows]


def _to_dict(row) -> dict:
    (sid, owner, kind, url, status, node, progress, attempts, findings,
     report, error, started, finished) = row
    return {
        "id": sid, "owner": owner, "kind": kind, "target_url": url,
        "status": status, "current_node": node, "progress": json.loads(progress),
        "attempts": json.loads(attempts), "findings": json.loads(findings),
        "report_path": report, "error": error,
        "started_at": started, "finished_at": finished,
    }
