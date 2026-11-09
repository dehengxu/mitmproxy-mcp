#!/usr/bin/env python3
"""Regression test for the vendored u33pk map_*_ctl tools.

Upstream u33pk declared the 'rule' parameter as a pydantic model while the
function body unpacked it again with **rule. FastMCP had already coerced the
JSON payload into a model instance, so **model raised
TypeError: argument after ** must be a mapping, not MapRemoteRule.

This test drives the server over stdio JSON-RPC and asserts both map tools
accept an 'add' call.

Usage: test_map_tools.py [path-to-mitmproxy-mcp-executable]
"""
import json
import subprocess
import sys


class McpClient:
    """Minimal MCP stdio client that matches responses by id."""

    def __init__(self, executable: str) -> None:
        self.proc = subprocess.Popen(
            [executable],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        self._next_id = 0

    def _send(self, method: str, params=None, notify: bool = False):
        message = {"jsonrpc": "2.0", "method": method}
        if not notify:
            self._next_id += 1
            message["id"] = self._next_id
        if params is not None:
            message["params"] = params
        self.proc.stdin.write(json.dumps(message) + "\n")
        self.proc.stdin.flush()
        return None if notify else self._next_id

    def _read_until(self, wanted_id: int) -> dict:
        while True:
            line = self.proc.stdout.readline()
            if not line.strip():
                continue
            payload = json.loads(line)
            if payload.get("id") == wanted_id:
                return payload

    def request(self, method: str, params=None) -> dict:
        return self._read_until(self._send(method, params))

    def notify(self, method: str, params=None) -> None:
        self._send(method, params, notify=True)

    def close(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def call_tool(client: McpClient, tool: str, arguments: dict) -> str:
    response = client.request(
        "tools/call", {"name": tool, "arguments": arguments}
    )
    if "error" in response:
        return "JSONRPC-ERROR " + response["error"].get("message", "")
    text = json.dumps(response.get("result", response), ensure_ascii=False)
    if '"success": true' in text or '"success":true' in text:
        return "SUCCESS"
    return "FAIL " + text[:300]


def main() -> int:
    executable = sys.argv[1] if len(sys.argv) > 1 else "mitmproxy-mcp"

    client = McpClient(executable)
    try:
        client.request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "map-tools-test", "version": "1.0"},
            },
        )
        client.notify("notifications/initialized", {})

        cases = [
            (
                "map_remote_ctl",
                {
                    "cmd": "add",
                    "rule": {
                        "id": "staging",
                        "filter": "~u example.com/api",
                        "url_regex": "https://example.com/api(.*)",
                        "replacement": "https://staging.example.com/api$1",
                    },
                },
            ),
            (
                "map_local_ctl",
                {
                    "cmd": "add",
                    "rule": {
                        "id": "local",
                        "filter": "~u example.com",
                        "url_regex": "https://example.com/x",
                        "local_path": "/etc/hosts",
                    },
                },
            ),
        ]

        failures = 0
        for tool, arguments in cases:
            verdict = call_tool(client, tool, arguments)
            if verdict == "SUCCESS":
                print(f"PASS {tool}: {verdict}")
            else:
                print(f"FAIL {tool}: {verdict}")
                failures += 1

        # Clean up whatever the test added.
        for tool in ("map_remote_ctl", "map_local_ctl"):
            call_tool(client, tool, {"cmd": "clear"})

        return 1 if failures else 0
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
