"""MCP server: target connector.

Exposes the whitelisted TargetClient as MCP tools so any MCP-compatible
agent (Claude Desktop, Cursor, etc.) can probe the audit target safely.
Run: python -m aegis.mcp_servers.target_connector
"""

from mcp.server.fastmcp import FastMCP

from aegis.targets.client import TargetClient

mcp = FastMCP("aegis-target-connector")
_clients: dict[str, TargetClient] = {}


def _client(url: str) -> TargetClient:
    url = url.rstrip("/")
    if url not in _clients:
        _clients[url] = TargetClient(url)  # whitelist enforced here
    return _clients[url]


@mcp.tool()
def target_health(target_url: str) -> dict:
    """Check whether the audit target is up and which defense level it runs."""
    return _client(target_url).health()


@mcp.tool()
def target_chat(target_url: str, message: str, history: list[dict] | None = None) -> str:
    """Send one chat message to the target and return its reply.

    Only whitelisted targets are reachable - anything else is refused.
    """
    return _client(target_url).chat(message, history or [])


if __name__ == "__main__":
    mcp.run()
