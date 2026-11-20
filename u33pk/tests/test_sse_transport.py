"""Tests for SSE transport support."""

from __future__ import annotations

import asyncio
import os
import sys
import time
from pathlib import Path

import pytest
from mcp import ClientSession
from mcp.client.sse import sse_client

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())  # pragma: no cover


@pytest.mark.asyncio
async def test_sse_server_lists_tools() -> None:
    """Start the MCP server in SSE mode and verify a client can list tools."""
    from mitmproxy_mcp.server import mcp

    host = "127.0.0.1"
    port = 18183
    mcp.settings.host = host
    mcp.settings.port = port

    server_task = asyncio.create_task(mcp.run_sse_async())

    # Wait for uvicorn to come up
    for _ in range(50):
        await asyncio.sleep(0.1)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=0.5
            )
            writer.close()
            await writer.wait_closed()
            break
        except OSError:
            continue
    else:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
        raise RuntimeError("SSE server did not start in time")

    try:
        async with sse_client(f"http://{host}:{port}/sse") as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.list_tools()
                tool_names = {t.name for t in result.tools}
                assert "proxy_ctl" in tool_names
                assert "http_ctl" in tool_names
                assert "websocket_ctl" in tool_names
                assert "tool_info" in tool_names
    finally:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass


def test_cli_sse_entrypoint_starts_and_serves_tools() -> None:
    """The ``--transport sse`` CLI entry point must actually start a server.

    Regression: ``main()`` called ``_configure_mcp_settings(...)``, a helper
    that was never defined anywhere in the package.  Every invocation of
    ``mitmproxy-mcp --transport sse`` died with a NameError before binding a
    port.  The unit tests above call ``mcp.run_sse_async()`` directly, so they
    never exercised the broken entry point -- that is why the defect survived
    since the initial integration commit.
    """
    import http.client
    import json
    import socket
    import subprocess
    import urllib.request

    # Pick a port without a race: keep the socket bound to port 0 so the OS
    # assigns the number, then close it right before the server binds it.
    # Releasing and re-binding later can hand the number to another process,
    # which is how this test once hit a stale server and got a 404.
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    env = dict(os.environ)
    src_dir = str(Path(__file__).resolve().parent.parent / "src")
    env["PYTHONPATH"] = src_dir + os.pathsep + env.get("PYTHONPATH", "")

    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "mitmproxy_mcp.server",
            "--transport",
            "sse",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    sse_conn = None
    try:
        endpoint = None
        deadline = time.time() + 30
        while time.time() < deadline:
            assert proc.poll() is None, (
                f"server exited early: {proc.stderr.read().decode(errors='replace')[-800:]}"
            )
            try:
                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                conn.request("GET", "/sse")
                resp = conn.getresponse()
                ctype = resp.getheader("content-type") or ""
                if resp.status == 200 and "text/event-stream" in ctype:
                    for _ in range(6):
                        line = resp.fp.readline().decode(errors="replace").strip()
                        if line.startswith("data:"):
                            endpoint = line[5:].strip()
                            break
                if endpoint:
                    # Keep the event stream open: the session id in the
                    # endpoint belongs to it, and posting to a closed
                    # session answers 404.
                    sse_conn = conn
                    break
                conn.close()
            except Exception:
                # The server may answer before the SSE route is ready.
                time.sleep(0.5)

        assert endpoint, "the SSE endpoint event never arrived"

        url = f"http://127.0.0.1:{port}{endpoint}"
        body = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "probe", "version": "1"},
                },
            }
        ).encode()
        req = urllib.request.Request(
            url, data=body, headers={"Content-Type": "application/json"}, method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            assert resp.status == 202
    finally:
        if sse_conn is not None:
            try:
                sse_conn.close()
            except Exception:
                pass
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:  # pragma: no cover - cleanup only
            proc.kill()
