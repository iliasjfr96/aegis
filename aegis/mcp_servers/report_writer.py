"""MCP server: report writer.

Render an Aegis HTML audit report from scan results, via MCP.
Run: python -m aegis.mcp_servers.report_writer
"""

from mcp.server.fastmcp import FastMCP

from aegis.graph.state import Finding, TargetProfile
from aegis.report.generator import generate_report

mcp = FastMCP("aegis-report-writer")


@mcp.tool()
def render_report(
    target_url: str,
    findings: list[dict],
    attempts_count: int,
    requests_used: int,
    profile: dict | None = None,
) -> str:
    """Generate the HTML audit report and return its file path."""
    path = generate_report(
        target_url=target_url,
        profile=TargetProfile(**profile) if profile else None,
        findings=[Finding(**f) for f in findings],
        attempts_count=attempts_count,
        requests_used=requests_used,
    )
    return str(path)


if __name__ == "__main__":
    mcp.run()
