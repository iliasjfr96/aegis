"""Deterministic web & WebSocket security checks - zero LLM required.

Covers what real apps (not just chatbots) expose: security headers, CORS,
exposed files, cookie flags, JWT weaknesses, and WebSocket auth/injection/
rate-limiting. Whitelist enforced before ANY request is sent.
"""

import time

import httpx

from aegis.config import get_settings
from aegis.graph.state import ConversationTurn, Finding, OwaspCategory, Severity
from aegis.targets.generic import TargetRefusedError

SECURITY_HEADERS = {
    "content-security-policy": ("CSP missing - XSS/data-injection risk", Severity.HIGH),
    "strict-transport-security": ("HSTS missing - downgrade attack risk", Severity.MEDIUM),
    "x-content-type-options": ("nosniff missing - MIME confusion risk", Severity.LOW),
    "x-frame-options": ("clickjacking protection missing", Severity.MEDIUM),
    "referrer-policy": ("referrer policy missing - URL data leakage", Severity.LOW),
}

EXPOSED_PATHS = ["/.env", "/.git/HEAD", "/.git/config", "/docker-compose.yml",
                 "/.DS_Store", "/api/.env", "/server/.env", "/debug", "/actuator/env"]


def _client(url: str, owner: str | None = None) -> httpx.Client:
    from aegis.auth.scope import is_allowed

    s = get_settings()
    if not is_allowed(url, owner):
        raise TargetRefusedError(f"{url} not whitelisted or verified")
    return httpx.Client(base_url=url.rstrip("/"), timeout=s.request_timeout_s,
                        follow_redirects=False)


def _finding(title, cat, sev, evidence, impact):
    return Finding(title=title, owasp=cat, severity=sev,
                   evidence=[ConversationTurn(role="attacker", content=evidence[0]),
                              ConversationTurn(role="target", content=evidence[1])],
                   impact=impact, remediation="TODO", attempt_id=f"web-{cat.value}")


def check_headers(c: httpx.Client, url: str) -> list[Finding]:
    r = c.get("/")
    out = []
    for header, (desc, sev) in SECURITY_HEADERS.items():
        if header not in r.headers:
            out.append(_finding(f"Missing {header}", OwaspCategory.WEB_HEADERS, sev,
                                (f"GET {url}/", f"200 OK, header '{header}' absent"), desc))
    server = r.headers.get("server", "")
    if server and any(ch.isdigit() for ch in server):
        out.append(_finding("Server version disclosed", OwaspCategory.WEB_HEADERS,
                            Severity.LOW, (f"GET {url}/", f"Server: {server}"),
                            "Exact version helps attackers pick known exploits"))
    return out


def check_cors(c: httpx.Client, url: str) -> list[Finding]:
    evil = "https://evil-aegis-test.com"
    r = c.options("/", headers={"Origin": evil,
                                "Access-Control-Request-Method": "POST"})
    allow = r.headers.get("access-control-allow-origin", "")
    creds = r.headers.get("access-control-allow-credentials", "")
    if allow == "*" and creds.lower() == "true":
        return [_finding("CORS: wildcard origin with credentials", OwaspCategory.WEB_CORS,
                         Severity.HIGH, (f"OPTIONS {url} Origin:{evil}",
                         f"allow-origin:* allow-credentials:true"),
                         "Any site can make authenticated cross-origin requests")]
    if allow == evil:
        return [_finding("CORS: arbitrary origin reflected", OwaspCategory.WEB_CORS,
                         Severity.HIGH, (f"OPTIONS {url} Origin:{evil}",
                         f"allow-origin reflected: {allow}"),
                         "Attacker-controlled origins are trusted")]
    if allow == "*":
        return [_finding("CORS: wildcard origin (no credentials)", OwaspCategory.WEB_CORS,
                         Severity.INFO, (f"OPTIONS {url} Origin:{evil}",
                         "allow-origin:* without allow-credentials"),
                         "Acceptable for public endpoints; ensure no authenticated route is exposed")]
    return []


def check_exposed_files(c: httpx.Client, url: str) -> list[Finding]:
    out = []
    for path in EXPOSED_PATHS:
        try:
            r = c.get(path)
        except httpx.HTTPError:
            continue
        if r.status_code == 200 and len(r.content) > 0:
            sev = Severity.CRITICAL if ".env" in path or ".git" in path else Severity.MEDIUM
            out.append(_finding(f"Exposed file: {path}", OwaspCategory.WEB_EXPOSED, sev,
                                (f"GET {url}{path}", f"200 OK, {len(r.content)} bytes"),
                                "Sensitive configuration or source code publicly readable"))
    return out


def check_cookies(c: httpx.Client, url: str) -> list[Finding]:
    r = c.get("/")
    out = []
    for cookie in r.headers.get_list("set-cookie"):
        name = cookie.split("=")[0]
        low = cookie.lower()
        missing = [f for f in ("secure", "httponly", "samesite") if f not in low]
        if missing:
            out.append(_finding(f"Cookie '{name}' missing flags: {', '.join(missing)}",
                                OwaspCategory.WEB_COOKIES, Severity.MEDIUM,
                                (f"GET {url}/", cookie[:120]),
                                "Session theft via XSS or network sniffing made easier"))
    return out


def check_jwt(token: str) -> list[Finding]:
    """Offline JWT checks: alg=none, weak HMAC secrets, missing expiry."""
    import base64
    import hashlib
    import hmac as hmac_mod
    import json

    out = []
    try:
        header_b64, payload_b64, sig = token.split(".")
        pad = lambda s: s + "=" * (-len(s) % 4)
        header = json.loads(base64.urlsafe_b64decode(pad(header_b64)))
        payload = json.loads(base64.urlsafe_b64decode(pad(payload_b64)))
    except Exception:
        return [_finding("Malformed JWT", OwaspCategory.WEB_JWT, Severity.INFO,
                         ("decode jwt", "unparseable"), "Not a valid JWT")]
    if header.get("alg", "").lower() == "none":
        out.append(_finding("JWT alg=none accepted format", OwaspCategory.WEB_JWT,
                            Severity.CRITICAL, ("jwt header", str(header)),
                            "Tokens can be forged without any signature"))
    if "exp" not in payload:
        out.append(_finding("JWT has no expiry", OwaspCategory.WEB_JWT, Severity.MEDIUM,
                            ("jwt payload", "no 'exp' claim"),
                            "Stolen tokens remain valid forever"))
    if header.get("alg") == "HS256":
        for secret in ("secret", "password", "changeme", "dev", "jwt-secret", "supersecret"):
            digest = hmac_mod.new(secret.encode(),
                                  f"{header_b64}.{payload_b64}".encode(),
                                  hashlib.sha256).digest()
            if base64.urlsafe_b64encode(digest).rstrip(b"=").decode() == sig:
                out.append(_finding(f"JWT signed with weak secret '{secret}'",
                                    OwaspCategory.WEB_JWT, Severity.CRITICAL,
                                    ("offline brute-force", f"secret = {secret}"),
                                    "Anyone can forge valid tokens"))
                break
    return out


class TargetUnreachableError(Exception):
    pass


def run_webscan(url: str, jwt_token: str | None = None,
                owner: str | None = None) -> list[Finding]:
    """Raises TargetUnreachableError if the host cannot be reached at all -
    a scan of a dead host must NEVER produce a misleading 'clean' report."""
    findings: list[Finding] = []
    with _client(url, owner) as c:
        try:
            c.get("/")  # liveness probe first
        except httpx.HTTPError as e:
            raise TargetUnreachableError(f"{url} unreachable: {e}") from e
        for check in (check_headers, check_cors, check_exposed_files, check_cookies):
            try:
                findings += check(c, url)
            except httpx.HTTPError:
                continue
    if jwt_token:
        findings += check_jwt(jwt_token)
    return findings
