#!/usr/bin/env python3
"""Unified MCP entry point for the two mitmproxy MCP servers.

Runs both upstream servers as child stdio processes and exposes a single MCP
server that merges their tools:

    spectral_<tool>   ->  snapspecter/mitmproxy-mcp
    u33pk_<tool>      ->  u33pk/mitmproxy-mcp

Tool input schemas are forwarded untouched; the prefix is stripped again when
the call is routed to the upstream.

The proxy is implemented directly on the MCP lowlevel server so that the
stdio framing, request/response correlation and upstream lifecycle stay under
our control.

Both upstreams keep their own proxy port (8081 / 8082), so capture sessions
stay isolated exactly as the standalone wrappers do.
"""
from __future__ import annotations

import asyncio
import contextlib
import os
import sys
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolResult,
    ListToolsResult,
    Tool,
)

SPECTRAL_BIN = os.environ.get(
    "SPECTRAL_BIN", os.path.expanduser("~/.local/bin/mitmproxy-mcp-spectral")
)
U33PK_BIN = os.environ.get(
    "U33PK_BIN", os.path.expanduser("~/.local/bin/mitmproxy-mcp-u33pk")
)

PREFIXES = {"spectral": SPECTRAL_BIN, "u33pk": U33PK_BIN}

PROTOCOL_VERSION = "2024-11-05"


class Upstream:
    """One child MCP server plus the tool table it exposes."""

    def __init__(self, prefix: str, command: str) -> None:
        self.prefix = prefix
        self.command = command
        self.session: ClientSession | None = None
        self.tools: dict[str, Tool] = {}
        self._ready = asyncio.Event()
        self._task: asyncio.Task | None = None

    async def _serve(self) -> None:
        params = StdioServerParameters(command=self.command, args=[])
        try:
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    self.session = session
                    self._ready.set()
                    await asyncio.Future()
        except Exception as exc:  # pragma: no cover - startup failure path
            print(
                f"[mitmproxy-mcp] upstream {self.prefix} failed: {exc}",
                file=sys.stderr,
                flush=True,
            )
            self._ready.set()

    def start(self) -> None:
        self._task = asyncio.create_task(self._serve())

    async def wait_ready(self, timeout: float = 30.0) -> bool:
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(self._ready.wait(), timeout=timeout)
        return self.session is not None

    async def load_tools(self) -> None:
        assert self.session is not None
        result = await self.session.list_tools()
        self.tools = {t.name: t for t in result.tools}


UPSTREAMS: dict[str, Upstream] = {
    flavor: Upstream(flavor, command) for flavor, command in PREFIXES.items()
}


def _route(name: str) -> tuple[Upstream, str] | None:
    for flavor, upstream in UPSTREAMS.items():
        prefix = f"{flavor}_"
        if name.startswith(prefix):
            bare = name[len(prefix) :]
            if bare in upstream.tools:
                return upstream, bare
    return None


def _exposed_tools() -> list[Tool]:
    out: list[Tool] = []
    for flavor, upstream in UPSTREAMS.items():
        for bare, tool in upstream.tools.items():
            raw_desc = getattr(tool, "description", "") or ""
            out.append(
                Tool(
                    name=f"{flavor}_{bare}",
                    description=(
                        f"[{flavor}] {raw_desc}\n\n"
                        f"来自 {flavor} 后端，调用时自动路由。"
                    ),
                    inputSchema=dict(getattr(tool, "inputSchema", {}) or {}),
                )
            )
    return out


async def _handle_call(name: str, arguments: dict[str, Any]) -> CallToolResult:
    routed = _route(name)
    if routed is None:
        return CallToolResult(
            content=[{"type": "text", "text": f"Unknown tool: {name}"}],
            isError=True,
        )
    upstream, bare = routed
    if upstream.session is None:
        return CallToolResult(
            content=[
                {"type": "text", "text": f"upstream {upstream.prefix} is not available"}
            ],
            isError=True,
        )
    try:
        result = await upstream.session.call_tool(bare, arguments or {})
    except Exception as exc:
        return CallToolResult(
            content=[{"type": "text", "text": f"{upstream.prefix} call failed: {exc}"}],
            isError=True,
        )
    return result


async def _build_server() -> Server:
    server: Server = Server("mitmproxy-mcp")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return _exposed_tools()

    @server.call_tool()
    async def call_tool(name: str, arguments: dict[str, Any]) -> Any:
        return await _handle_call(name, arguments)

    return server


async def _main() -> None:
    for upstream in UPSTREAMS.values():
        upstream.start()

    for flavor, upstream in UPSTREAMS.items():
        if not await upstream.wait_ready():
            print(
                f"[mitmproxy-mcp] upstream {flavor} did not become ready",
                file=sys.stderr,
                flush=True,
            )
            continue
        await upstream.load_tools()

    count = sum(len(u.tools) for u in UPSTREAMS.values())
    print(
        f"[mitmproxy-mcp] ready: {len(UPSTREAMS)} upstreams, {count} tools",
        file=sys.stderr,
        flush=True,
    )

    server = await _build_server()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main() -> None:
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(_main())


if __name__ == "__main__":
    main()
