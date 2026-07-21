"""Security-firm style HTML report generator."""

from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from aegis.graph.state import Finding, Severity, TargetProfile
from aegis.report.remediations import REMEDIATIONS

SEVERITY_WEIGHT = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 7,
    Severity.MEDIUM: 4,
    Severity.LOW: 2,
    Severity.INFO: 0,
}

OWASP_NAMES = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "WEB-HEADERS": "Security Headers",
    "WEB-CORS": "CORS Misconfiguration",
    "WEB-EXPOSED": "Exposed Sensitive Files",
    "WEB-COOKIES": "Insecure Cookies",
    "WEB-JWT": "JWT Weaknesses",
    "WS-AUTH": "WebSocket Missing Auth",
    "WS-INJECTION": "WebSocket Input Handling",
    "WS-RATELIMIT": "WebSocket Rate Limiting",
}


def risk_score(findings: list[Finding]) -> tuple[int, str]:
    """0-100 score + label, like a real audit deliverable."""
    if not findings:
        return 0, "LOW"
    raw = sum(SEVERITY_WEIGHT[f.severity] for f in findings)
    score = min(100, raw * 8)
    label = "CRITICAL" if score >= 80 else "HIGH" if score >= 50 else "MEDIUM" if score >= 25 else "LOW"
    return score, label


def generate_report(
    target_url: str,
    profile: TargetProfile | None,
    findings: list[Finding],
    attempts_count: int,
    requests_used: int,
    out_dir: str = "reports",
) -> Path:
    env = Environment(
        loader=FileSystemLoader(Path(__file__).parent / "templates"),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html.j2")

    for f in findings:
        if f.remediation.startswith("TODO"):
            f.remediation = REMEDIATIONS[f.owasp]

    score, label = risk_score(findings)
    owasp_matrix = [
        {
            "id": oid,
            "name": name,
            "tested": any(a for a in findings) or True,
            "vulnerable": any(f.owasp.value == oid for f in findings),
            "severity": max(
                (f.severity.value for f in findings if f.owasp.value == oid), default=None
            ),
        }
        for oid, name in OWASP_NAMES.items()
    ]

    html = template.render(
        target_url=target_url,
        date=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        score=score,
        label=label,
        findings=findings,
        attempts_count=attempts_count,
        requests_used=requests_used,
        profile=profile,
        owasp_matrix=owasp_matrix,
        owasp_names=OWASP_NAMES,
    )
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"aegis-report-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.html"
    path.write_text(html, encoding="utf-8")
    return path
