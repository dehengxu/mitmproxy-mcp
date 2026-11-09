#!/usr/bin/env python3
"""Test the unified entry's merge + routing logic against stub upstreams.

Runs two stub MCP servers (flavors 'alpha' and 'beta') and checks that the
aggregator exposes both under prefixed names, keeps their schemas, and routes
calls to the correct backend.

This needs no mitmproxy installation, so it can run in CI.

Usage: test_unified_merging.py
"""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
STUB = os.path.join(HERE, "stub_upstream.py")
AGGREGATOR = os.path.join(HERE, "mitmproxy_mcp_unified.py")


class Client:
    def __init__(self, executable: str, env: dict) -> None:
        self.proc = subprocess.Popen(
            [executable, AGGREGATOR],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
            env=env,
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


def main() -> int:
    import sys

    with tempfile.TemporaryDirectory() as tmp:
        alpha = os.path.join(tmp, "alpha_stub")
        beta = os.path.join(tmp, "beta_stub")
        for path, flavor in ((alpha, "alpha"), (beta, "beta")):
            with open(path, "w") as fh:
                fh.write('#!/bin/bash\nSTUB_FLAVOR=' + flavor + ' exec '
                         + sys.executable + ' ' + STUB + ' "$@"\n')
            os.chmod(path, 0o755)

        env = dict(os.environ)
        env["SPECTRAL_BIN"] = alpha
        env["U33PK_BIN"] = beta

        client = Client(sys.executable, env)
        failures = []
        try:
            client.request(
                "initialize",
                {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "merge-test", "version": "1.0"},
                },
            )
            client.notify("notifications/initialized", {})

            tools = client.request("tools/list").get("result", {}).get("tools", [])
            names = sorted(t["name"] for t in tools)
            print("tools:", names)

            expected = [
                "spectral_alpha_tool",
                "spectral_beta_tool",
                "u33pk_alpha_tool",
                "u33pk_beta_tool",
            ]
            if names != expected:
                failures.append(f"expected {expected}, got {names}")
            else:
                print("PASS both upstreams merged under prefixed names")

            for tool in tools:
                if tool["name"] == "spectral_alpha_tool":
                    props = tool.get("inputSchema", {}).get("properties", {})
                    if "value" not in props:
                        failures.append("upstream schema was lost during merge")
                    else:
                        print("PASS upstream schema survived the merge")

            resp = client.request(
                "tools/call",
                {"name": "u33pk_alpha_tool", "arguments": {"value": 3}},
            )
            text = json.dumps(resp, ensure_ascii=False)
            if "beta:alpha_tool" not in text:
                failures.append(f"call was not routed to the beta stub: {text[:200]}")
            else:
                print("PASS call routed to the correct upstream")
        finally:
            client.close()

    if failures:
        for item in failures:
            print(f"FAIL {item}")
        return 1
    print("all unified merging checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
