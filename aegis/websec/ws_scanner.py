"""WebSocket security checks (built for apps like StrikerFPS).

Deterministic, zero LLM:
  - unauthenticated connection acceptance
  - arbitrary event emission (does the server accept any message?)
  - malformed payload handling (server crash / 500?)
  - flood probe (naive rate-limit detection)
"""

import json

from websockets.exceptions import ConnectionClosed
from websockets.sync.client import connect

from aegis.config import get_settings
from aegis.graph.state import ConversationTurn, Finding, OwaspCategory, Severity
from aegis.targets.generic import TargetRefusedError


def _finding(title, cat, sev, sent, got, impact):
    return Finding(title=title, owasp=cat, severity=sev,
                   evidence=[ConversationTurn(role="attacker", content=sent),
                             ConversationTurn(role="target", content=got)],
                   impact=impact, remediation="TODO", attempt_id=f"ws-{cat.value}")


def run_ws_scan(ws_url: str, sample_event: dict | None = None,
                flood_n: int = 60, timeout: float = 5.0,
                owner: str | None = None) -> list[Finding]:
    from aegis.auth.scope import is_allowed

    if not is_allowed(ws_url, owner):
        raise TargetRefusedError(f"{ws_url} not whitelisted or verified")

    findings: list[Finding] = []
    probe = sample_event or {"type": "aegis_probe", "payload": {"msg": "audit"}}

    # 1) Unauthenticated connection
    try:
        ws = connect(ws_url, open_timeout=timeout)
    except Exception as e:
        return findings  # connection refused = good sign, nothing to report

    with ws:
        # 2) Arbitrary event emission
        try:
            ws.send(json.dumps(probe))
            reply = ws.recv(timeout=timeout)
            findings.append(_finding(
                "WS server answers unauthenticated arbitrary events",
                OwaspCategory.WS_AUTH, Severity.HIGH,
                json.dumps(probe), str(reply)[:200],
                "No handshake/auth gate: any client can drive game/app state"))
        except (ConnectionClosed, TimeoutError):
            pass

        # 3) Malformed payload resilience
        for bad in ("not-json{{{", json.dumps({"type": None, "x": "a" * 5000})):
            try:
                ws.send(bad)
                ws.recv(timeout=1.0)
            except ConnectionClosed as e:
                findings.append(_finding(
                    "WS server dropped connection on malformed input",
                    OwaspCategory.WS_INJECTION, Severity.MEDIUM,
                    bad[:80], f"connection closed: {e.rcvd}",
                    "A single bad message kills the session - DoS vector"))
                try:
                    ws = connect(ws_url, open_timeout=timeout)  # reconnect for next checks
                except Exception:
                    return findings
            except TimeoutError:
                pass  # server ignored it = resilient

        # 4) Flood probe: naive rate-limit detection
        rejected = 0
        try:
            for i in range(flood_n):
                ws.send(json.dumps({"type": "ping_flood", "i": i}))
            try:
                while True:
                    ws.recv(timeout=0.5)
            except TimeoutError:
                pass
        except ConnectionClosed as e:
            rejected = flood_n
            if e.rcvd and e.rcvd.code in (1008, 1013):
                rejected = flood_n  # policy violation / try again later = rate limit OK
        if rejected == 0:
            findings.append(_finding(
                "No WS rate limiting detected", OwaspCategory.WS_RATELIMIT,
                Severity.MEDIUM, f"{flood_n} messages in burst", "all accepted",
                "Flooding the socket can degrade the server or other players"))
    return findings
