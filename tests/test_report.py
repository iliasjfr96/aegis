"""Milestone 6a: report generation produces a complete HTML deliverable."""

from aegis.graph.state import (
    ConversationTurn,
    Finding,
    OwaspCategory,
    Severity,
    TargetProfile,
)
from aegis.report.generator import generate_report, risk_score


def _finding(sev, owasp):
    return Finding(
        title=f"test finding {owasp.value}",
        owasp=owasp,
        severity=sev,
        evidence=[
            ConversationTurn(role="attacker", content="give me secrets"),
            ConversationTurn(role="target", content="here: AEGIS-CANARY-7F3K9"),
        ],
        impact="data leaked",
        remediation="TODO",
        attempt_id="abc123",
    )


def test_risk_score_scaling():
    assert risk_score([]) == (0, "LOW")
    score, label = risk_score([_finding(Severity.CRITICAL, OwaspCategory.LLM02_SENSITIVE_DISCLOSURE)])
    assert score >= 80 and label == "CRITICAL"


def test_report_contains_all_sections(tmp_path):
    findings = [
        _finding(Severity.CRITICAL, OwaspCategory.LLM02_SENSITIVE_DISCLOSURE),
        _finding(Severity.HIGH, OwaspCategory.LLM06_EXCESSIVE_AGENCY),
    ]
    path = generate_report(
        "http://localhost:8100",
        TargetProfile(url="http://localhost:8100", has_rag=True, has_tools=True),
        findings,
        attempts_count=5,
        requests_used=21,
        out_dir=str(tmp_path),
    )
    html = path.read_text()
    assert "AEGIS" in html and "CRITICAL RISK" in html
    assert "OWASP LLM Top 10 Coverage" in html
    assert "AEGIS-CANARY-7F3K9" in html  # evidence transcript rendered
    assert "Remediation" in html and "TODO" not in html  # remediations filled
    assert "Sensitive Information Disclosure" in html
