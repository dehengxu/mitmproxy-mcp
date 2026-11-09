#!/usr/bin/env python3
"""Regression test for the unified mitmproxy MCP entry point.

Asserts that the aggregator exposes both upstreams' tools under prefixed
names, that the raw upstream schemas survive the merge, and that calls are
routed to the right backend.

Usage: test_unified_entry.py [path-to-mitmproxy-mcp-unified]
"""
import json
import subprocess
import sys


class Client:
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

    def call(self, tool: str, arguments: dict) -> dict:
        return self.request(
            "tools/call", {"name": tool, "arguments": arguments}
        )

    def close(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def main() -> int:
    executable = (
        sys.argv[1]
        if len(sys.argv) > 1
        else "mitmproxy-mcp-unified"
    )

    failures = []
    client = Client(executable)
    try:
        client.request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "unified-test", "version": "1.0"},
            },
        )
        client.notify("notifications/initialized", {})

        tools = client.request("tools/list").get("result", {}).get("tools", [])
        names = sorted(t["name"] for t in tools)

        spectral = [n for n in names if n.startswith("spectral_")]
        u33pk = [n for n in names if n.startswith("u33pk_")]
        other = [n for n in names if not n.startswith(("spectral_", "u33pk_"))]

        print(f"tool count: {len(names)} (spectral={len(spectral)}, u33pk={len(u33pk)})")
        if len(spectral) != 25:
            failures.append(f"expected 25 spectral tools, got {len(spectral)}")
        if len(u33pk) != 12:
            failures.append(f"expected 12 u33pk tools, got {len(u33pk)}")
        if other:
            failures.append(f"unprefixed tools leaked: {other}")

        # The raw upstream schema must survive the merge.
        for tool in tools:
            if tool["name"] == "spectral_start_proxy":
                props = tool.get("inputSchema", {}).get("properties", {})
                if "port" not in props:
                    failures.append("spectral_start_proxy lost its input schema")
                else:
                    print("PASS spectral_start_proxy keeps its upstream schema")

        # Routing: each backend must answer its own tools.
        cases = [
            ("spectral_start_proxy", {"port": 8081}),
            ("u33pk_proxy_ctl", {"cmd": "start", "port": 8082}),
        ]
        for tool, args in cases:
            resp = client.call(tool, args)
            if "error" in resp:
                failures.append(f"{tool} -> {resp['error'].get('message')}")
            elif resp.get("result", {}).get("isError"):
                failures.append(f"{tool} returned isError")
            else:
                print(f"PASS {tool} routed and succeeded")

        # Unknown tool must fail gracefully, not crash the server.
        resp = client.call("definitely_not_a_tool", {})
        if "error" in resp:
            failures.append("unknown tool raised a protocol error")
        else:
            print("PASS unknown tool handled gracefully")

        # Clean up any proxy we started.
        client.call("spectral_stop_proxy", {})
        client.call("u33pk_proxy_ctl", {"cmd": "stop"})
    finally:
        client.close()

    if failures:
        for item in failures:
            print(f"FAIL {item}")
        return 1
    print("all unified entry checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
