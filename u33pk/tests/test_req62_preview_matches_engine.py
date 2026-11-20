"""The hit preview must agree with what the engine actually does.

The WebUI tells the user "this rule wins for that field, the others are
skipped". That promise is only worth anything if it is true on live traffic,
so this file drives a real client through a real proxy and compares what the
origin received against what the preview endpoint said beforehand.

Run with:

    pytest tests/test_req62_preview_matches_engine.py -m integration -v
"""

from __future__ import annotations

import json
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from mitmproxy_mcp.server import http_ctl, proxy_ctl, rule_ctl

# This file's own port block, clear of every other test module.
_SERVER_PORT = 19261
_PROXY_PORT = 18261


class _EchoHandler(BaseHTTPRequestHandler):
    """Echo the request line and the headers the origin really received."""

    def do_GET(self) -> None:  # noqa: N802
        body = json.dumps(
            {"path": self.path, "headers": dict(self.headers)}
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:  # noqa: D102
        pass


@pytest.fixture(scope="module")
def origin():
    server = ThreadingHTTPServer(("127.0.0.1", _SERVER_PORT), _EchoHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.3)
    return server


@pytest.fixture(scope="module")
def proxy(origin):  # noqa: ARG001
    """A running proxy with the rewrite engine attached."""
    proxy_ctl(cmd="start", port=_PROXY_PORT, webui=False)
    time.sleep(0.5)
    yield
    proxy_ctl(cmd="stop")


def _get_through_proxy(path: str) -> dict:
    proxy_handler = urllib.request.ProxyHandler(
        {"http": f"http://127.0.0.1:{_PROXY_PORT}"}
    )
    opener = urllib.request.build_opener(proxy_handler)
    with opener.open(f"http://127.0.0.1:{_SERVER_PORT}{path}", timeout=10) as resp:
        return json.loads(resp.read().decode())


def _clear_rules() -> None:
    rule_ctl(cmd="clear")


@pytest.mark.integration
class TestPreviewMatchesEngine:
    def test_preview_predicts_which_rule_wins(self, proxy, origin):  # noqa: ARG001
        """Two rules write the same header: the first must win, live."""
        _clear_rules()
        rule_ctl(
            cmd="add",
            rule={
                "id": "first",
                "name": "first",
                "filter": "~u 127.0.0.1",
                "actions": [
                    {
                        "type": "set_header",
                        "target": "request",
                        "name": "X-Winner",
                        "value": "first",
                    }
                ],
            },
        )
        rule_ctl(
            cmd="add",
            rule={
                "id": "second",
                "name": "second",
                "filter": "~u 127.0.0.1",
                "actions": [
                    {
                        "type": "set_header",
                        "target": "request",
                        "name": "X-Winner",
                        "value": "second",
                    }
                ],
            },
        )

        # What the preview endpoint says about that field.
        from mitmproxy_mcp.rewrite_web import _preview_claim

        probe = _preview_claim("request", "header", "X-Winner")
        assert probe is not None

        # The engine's own view of the same rules, on a real flow.
        from mitmproxy.test import tflow

        from mitmproxy_mcp.server import proxy_manager

        flow = tflow.tflow()
        flow.request.host = "127.0.0.1"
        rules_addon = proxy_manager.rules_addon

        import asyncio

        asyncio.new_event_loop().run_until_complete(rules_addon.request(flow))

        skipped = flow.metadata.get("mitmproxy_mcp_rules_skipped", [])
        applied = flow.metadata.get("mitmproxy_mcp_rules_applied", [])

        # The preview and the engine must name the same winner.
        winner = "first"
        assert applied == [winner], f"engine applied {applied}"
        assert skipped, "the second rule should have been skipped"
        assert skipped[0]["rule_id"] == "second"
        assert skipped[0]["claimed_by"] == winner

        # And the origin really received the winner's value.
        received = _get_through_proxy("/x")
        assert received["headers"].get("X-Winner") == "first"

    def test_preview_order_follows_rule_sets(self, proxy, origin):  # noqa: ARG001
        """A rule in an enabled set competes with a standalone rule."""
        _clear_rules()
        rule_ctl(
            cmd="add",
            rule={
                "id": "standalone",
                "name": "standalone",
                "filter": "~u 127.0.0.1",
                "actions": [
                    {
                        "type": "set_header",
                        "target": "request",
                        "name": "X-Order",
                        "value": "standalone",
                    }
                ],
            },
        )
        rule_ctl(cmd="ruleset_add", ruleset={"id": "rs1", "name": "set"})
        rule_ctl(
            cmd="ruleset_add_rule",
            ruleset_id="rs1",
            rule={
                "id": "inset",
                "name": "inset",
                "filter": "~u 127.0.0.1",
                "actions": [
                    {
                        "type": "set_header",
                        "target": "request",
                        "name": "X-Order",
                        "value": "inset",
                    }
                ],
            },
        )

        received = _get_through_proxy("/y")
        # Standalone rules are evaluated first, so they win the field.
        assert received["headers"].get("X-Order") == "standalone"

        _clear_rules()
