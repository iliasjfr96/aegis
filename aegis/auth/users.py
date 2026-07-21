"""User accounts + BYOK (bring-your-own-key) provider credentials.

- Passwords: bcrypt via passlib
- Sessions: JWT (HS256)
- Provider keys: Fernet-encrypted at rest (AEGIS_SECRET_KEY derives both keys)
- Storage: SQLite (swap for Postgres in prod)
"""

import base64
import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path

import bcrypt
import jwt
from cryptography.fernet import Fernet

def _db_path() -> str:
    return os.environ.get("AEGIS_DB", "aegis_users.db")
JWT_ALG = "HS256"
JWT_TTL_S = 7 * 24 * 3600


def _hash_pw(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def _verify_pw(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


def _secret() -> bytes:
    return os.environ.get("AEGIS_SECRET_KEY", "dev-only-secret-change-me").encode()


def _fernet() -> Fernet:
    key = base64.urlsafe_b64encode(hashlib.sha256(b"fernet:" + _secret()).digest())
    return Fernet(key)


def _jwt_key() -> bytes:
    return hashlib.sha256(b"jwt:" + _secret()).digest()


def _db() -> sqlite3.Connection:
    db = _db_path()
    if "/" in db:
        Path(db).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS users(
           email TEXT PRIMARY KEY, pw_hash TEXT, created_at REAL)"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS provider_keys(
           email TEXT, provider TEXT, enc_key TEXT, model TEXT, updated_at REAL,
           PRIMARY KEY(email, provider))"""
    )
    return conn


def register(email: str, password: str) -> str:
    conn = _db()
    try:
        conn.execute(
            "INSERT INTO users VALUES (?,?,?)",
            (email.lower(), _hash_pw(password), time.time()),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise ValueError("email already registered")
    return issue_token(email)


def login(email: str, password: str) -> str:
    row = _db().execute("SELECT pw_hash FROM users WHERE email=?", (email.lower(),)).fetchone()
    if not row or not _verify_pw(password, row[0]):
        raise ValueError("invalid credentials")
    return issue_token(email)


def issue_token(email: str) -> str:
    return jwt.encode(
        {"sub": email.lower(), "exp": int(time.time()) + JWT_TTL_S}, _jwt_key(), algorithm=JWT_ALG
    )


def verify_token(token: str) -> str:
    payload = jwt.decode(token, _jwt_key(), algorithms=[JWT_ALG])
    return payload["sub"]


def save_provider_key(email: str, provider: str, api_key: str, model: str = "") -> None:
    enc = _fernet().encrypt(api_key.encode()).decode()
    conn = _db()
    conn.execute(
        "INSERT OR REPLACE INTO provider_keys VALUES (?,?,?,?,?)",
        (email.lower(), provider, enc, model, time.time()),
    )
    conn.commit()


def get_provider_key(email: str, provider: str) -> dict | None:
    row = _db().execute(
        "SELECT enc_key, model FROM provider_keys WHERE email=? AND provider=?",
        (email.lower(), provider),
    ).fetchone()
    if not row:
        return None
    return {"api_key": _fernet().decrypt(row[0].encode()).decode(), "model": row[1]}


def list_providers(email: str) -> list[dict]:
    rows = _db().execute(
        "SELECT provider, model, updated_at FROM provider_keys WHERE email=?",
        (email.lower(),),
    ).fetchall()
    return [{"provider": r[0], "model": r[1], "updated_at": r[2]} for r in rows]
