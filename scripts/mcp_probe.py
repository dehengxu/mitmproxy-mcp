#!/usr/bin/env python3
"""Ask an MCP server for its tool list over stdio JSON-RPC.

Usage: mcp_probe.py <path-to-mcp-executable> [extra args...]
Prints "<count>\n<comma-separated-tool-names>".
"""
import json
import subprocess
import sys

exe = sys.argv[1]
args = sys.argv[2:]

proc = subprocess.Popen(
    [exe, *args],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.DEVNULL,
    text=True,
    bufsize=1,
)


def send(obj):
    proc.stdin.write(json.dumps(obj) + "\n")
    proc.stdin.flush()


def read():
    line = proc.stdout.readline()
    return json.loads(line) if line.strip() else {}


try:
    send({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "mcp-probe", "version": "1.0"},
        },
    })
    read()
    send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
    send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    resp = read()
    names = sorted(t["name"] for t in resp.get("result", {}).get("tools", []))
    print(len(names))
    print(",".join(names))
except Exception as exc:  # noqa: BLE001 - probe must never crash the caller
    print(f"probe error: {exc}", file=sys.stderr)
    sys.exit(1)
finally:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
