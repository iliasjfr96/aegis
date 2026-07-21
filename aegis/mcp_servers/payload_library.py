"""MCP server: attack payload library.

Query the Aegis attack library (techniques, openers, OWASP mapping) from
any MCP client. Run: python -m aegis.mcp_servers.payload_library
"""

from mcp.server.fastmcp import FastMCP

from aegis.attacks.library import GOALS, OPENERS, TECHNIQUE_OWASP
from aegis.graph.state import AttackTechnique

mcp = FastMCP("aegis-payload-library")


@mcp.tool()
def list_techniques() -> list[dict]:
    """List all attack techniques with their OWASP category and goal."""
    return [
        {"technique": t.value, "owasp": TECHNIQUE_OWASP[t].value, "goal": GOALS[t]}
        for t in AttackTechnique
    ]


@mcp.tool()
def get_openers(technique: str) -> list[str]:
    """Get the scripted opening messages for a given technique."""
    t = AttackTechnique(technique)
    return OPENERS[t]


@mcp.tool()
def owasp_mapping() -> dict:
    """Return the technique -> OWASP LLM Top 10 mapping."""
    return {t.value: TECHNIQUE_OWASP[t].value for t in AttackTechnique}


if __name__ == "__main__":
    mcp.run()
