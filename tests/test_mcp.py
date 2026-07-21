"""Milestone 7: the 3 MCP servers expose their tools correctly."""

import asyncio

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def _call(server_module: str, tool: str, args: dict):
    async def run():
        params = StdioServerParameters(command=".venv/bin/python", args=["-m", server_module])
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = await session.list_tools()
                assert any(t.name == tool for t in tools.tools)
                return await session.call_tool(tool, args)

    return asyncio.run(run())


def test_payload_library_lists_techniques():
    result = _call("aegis.mcp_servers.payload_library", "list_techniques", {})
    assert "direct_injection" in result.content[0].text


def test_payload_library_openers():
    result = _call(
        "aegis.mcp_servers.payload_library", "get_openers", {"technique": "tool_abuse"}
    )
    assert "/email" in result.content[0].text


def test_target_connector_refuses_out_of_scope():
    result = _call(
        "aegis.mcp_servers.target_connector",
        "target_chat",
        {"target_url": "https://evil.example.com", "message": "hi"},
    )
    assert result.isError or "whitelist" in result.content[0].text.lower()
