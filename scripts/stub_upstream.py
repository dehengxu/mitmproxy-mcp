#!/usr/bin/env python3
"""Minimal stub MCP server used to test the unified entry without mitmproxy.

Exposes two tools: 'alpha_tool' and 'beta_tool'. The unified entry prefixes them
with the stub's flavor name, which is what the routing test asserts.
"""
import asyncio
import contextlib
import os
import sys

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import ListToolsResult, Tool

FLAVOR = os.environ.get("STUB_FLAVOR", "stub")


async def main() -> None:
    server: Server = Server(f"stub-{FLAVOR}")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name="alpha_tool",
                description=f"alpha from {FLAVOR}",
                inputSchema={
                    "type": "object",
                    "properties": {"value": {"type": "integer", "default": 7}},
                },
            ),
            Tool(
                name="beta_tool",
                description=f"beta from {FLAVOR}",
                inputSchema={"type": "object", "properties": {}},
            ),
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict):
        return [{"type": "text", "text": f"{FLAVOR}:{name}:{arguments}"}]

    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream, write_stream, server.create_initialization_options()
        )


if __name__ == "__main__":
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(main())
