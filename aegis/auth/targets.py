"""User-owned target verification (like Detectify's domain verification).

Flow:
  1. User registers a target URL -> gets a unique token
  2. User serves it at https://target/.well-known/aegis-verify.txt
  3. Aegis fetches that URL, matches the token -> target verified
  4. Verified targets are scannable BY THAT USER ONLY

The global env whitelist stays as the admin-level scope (always allowed).
"""

import secrets
import sqlite3
import time

import httpx

from aegis.auth.users import _db

VERIFY_PATH = "/.well-known/aegis-verify.txt"


def _ensure_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """CREATE TABLE IF NOT EXISTS targets(
           email TEXT, url TEXT, token TEXT, verified INTEGER, created_at REAL,
           PRIMARY KEY(email, url))"""
    )


def register_target(email: str, url: str) -> dict:
    url = url.rstrip("/")
    token = f"aegis-verify-{secrets.token_urlsafe(24)}"
    conn = _db()
    _ensure_table(conn)
    row = conn.execute(
        "SELECT token, verified FROM targets WHERE email=? AND url=?", (email, url)
    ).fetchone()
    if row:
        return {"url": url, "token": row[0], "verified": bool(row[1]), "verify_path": VERIFY_PATH}
    conn.execute(
        "INSERT INTO targets VALUES (?,?,?,?,?)",
        (email, url, token, 0, time.time()),
    )
    conn.commit()
    return {"url": url, "token": token, "verified": False, "verify_path": VERIFY_PATH}


def list_targets(email: str) -> list[dict]:
    conn = _db()
    _ensure_table(conn)
    rows = conn.execute(
        "SELECT url, token, verified, created_at FROM targets WHERE email=?", (email,)
    ).fetchall()
    return [{"url": r[0], "token": r[1], "verified": bool(r[2]), "created_at": r[3]}
            for r in rows]


def is_verified_for(email: str, url: str) -> bool:
    url = url.rstrip("/")
    conn = _db()
    _ensure_table(conn)
    rows = conn.execute(
        "SELECT url FROM targets WHERE email=? AND verified=1", (email,)
    ).fetchall()
    return any(url == r[0] or url.startswith(r[0] + "/") for r in rows)


def verify_target(email: str, url: str, fetcher=None) -> dict:
    """Fetch the verification file and check the token."""
    url = url.rstrip("/")
    conn = _db()
    _ensure_table(conn)
    row = conn.execute(
        "SELECT token FROM targets WHERE email=? AND url=?", (email, url)
    ).fetchone()
    if not row:
        return {"verified": False, "error": "target not registered"}
    token = row[0]
    try:
        if fetcher:
            body = fetcher(url + VERIFY_PATH)
        else:
            body = httpx.get(url + VERIFY_PATH, timeout=10, follow_redirects=True).text
    except Exception as e:
        return {"verified": False, "error": f"cannot fetch {VERIFY_PATH}: {e}"}
    if token in body:
        conn.execute(
            "UPDATE targets SET verified=1 WHERE email=? AND url=?", (email, url)
        )
        conn.commit()
        return {"verified": True}
    return {"verified": False, "error": "token not found in verification file"}
