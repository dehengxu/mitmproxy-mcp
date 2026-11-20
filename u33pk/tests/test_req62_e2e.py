"""End-to-end tests for REQ-6.2: a real proxy, a real origin, real rewrites.

Unit tests with a hand-made flow cannot show that the URL mitmproxy actually
sends carries the rewritten query string, or that a rule set's master switch
takes effect on live traffic.  This file drives a real client through the
proxy and inspects what the origin received.

Run with:

    pytest tests/test_req62_e2e.py -m integration -v
"""

from __future__ import annotations

import json
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from mitmproxy_mcp.server import http_ctl, proxy_ctl, rule_ctl

# This file's own port block, clear of every other test module.
_SERVER_PORT = 19251
_PROXY_PORT = 18251


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
    """One origin server for the whole module.

    The thread is a daemon, so the process exit is what ends it; stopping it
    mid-run would only make later tests in this file flaky.
    """
    server = ThreadingHTTPServer(("127.0.0.1", _SERVER_PORT), _EchoHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    time.sleep(0.3)
    return server


@pytest.fixture(scope="module")
def proxy(origin):
    """One proxy for the whole module.

    Starting and stopping the proxy between tests races the listening socket
    (a just-released port is not immediately bindable), which made individual
    tests flaky for reasons unrelated to what they check.  Each test instead
    resets the rule configuration and uses a path only it touches.
    """
    r = proxy_ctl(cmd="start", port=_PROXY_PORT)
    assert r["success"] is True, r
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{_SERVER_PORT}/health", timeout=1
            ):
                break
        except urllib.error.URLError:
            time.sleep(0.2)
    yield _PROXY_PORT
    proxy_ctl(cmd="stop")


@pytest.fixture(autouse=True)
def _clean_rules():
    try:
        rule_ctl(cmd="clear")
        http_ctl(cmd="clear")
    except Exception:
        pass
    yield
    try:
        rule_ctl(cmd="clear")
        http_ctl(cmd="clear")
    except Exception:
        pass


def _get_via_proxy(
    url: str, proxy_port: int, timeout: float = 15
) -> tuple[int, dict]:
    handler = urllib.request.ProxyHandler({"http": f"http://127.0.0.1:{proxy_port}"})
    opener = urllib.request.build_opener(handler)
    try:
        with opener.open(urllib.request.Request(url, method="GET"), timeout=timeout) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, {}


def _latest_flow(path_contains: str) -> dict:
    deadline = time.time() + 10
    while time.time() < deadline:
        for flow in http_ctl(cmd="list")["flows"]:
            if path_contains in flow["request"]["path"]:
                return flow
        time.sleep(0.2)
    raise AssertionError(f"no captured flow containing {path_contains!r}")


def _headers(flow: dict) -> dict[str, str]:
    return {h["name"].lower(): h["value"] for h in flow["request"]["headers"]}


@pytest.mark.integration
def test_set_query_reaches_the_origin_encoded(proxy) -> None:
    """A rewritten query parameter must arrive at the origin URL-encoded."""
    proxy_port = proxy
    assert rule_ctl(
        cmd="add",
        rule={
            "id": "query",
            "filter": f"~u 127.0.0.1:{_SERVER_PORT}/search",
            "phase": "request",
            "actions": [
                {"type": "set_query", "name": "q", "value": "a b&c=d"},
                {"type": "set_query", "name": "page", "value": "2"},
            ],
        },
    )["success"] is True

    status, payload = _get_via_proxy(f"http://127.0.0.1:{_SERVER_PORT}/search?sort=asc", proxy_port)
    assert status == 200
    path = payload["path"]
    assert path.startswith("/search?")
    params = dict(urllib.parse.parse_qsl(path.split("?", 1)[1]))
    assert params["q"] == "a b&c=d"
    assert params["page"] == "2"
    assert params["sort"] == "asc"


@pytest.mark.integration
def test_remove_query_reaches_the_origin(proxy) -> None:
    proxy_port = proxy
    assert rule_ctl(
        cmd="add",
        rule={
            "id": "drop",
            "filter": f"~u 127.0.0.1:{_SERVER_PORT}/drop",
            "phase": "request",
            "actions": [{"type": "remove_query", "name": "debug"}],
        },
    )["success"] is True

    status, payload = _get_via_proxy(
        f"http://127.0.0.1:{_SERVER_PORT}/drop?debug=1&keep=2", proxy_port
    )
    assert status == 200
    params = dict(urllib.parse.parse_qsl(payload["path"].split("?", 1)[1]))
    assert params == {"keep": "2"}


@pytest.mark.integration
def test_first_match_wins_on_live_traffic_and_skip_is_recorded(proxy) -> None:
    proxy_port = proxy
    for rid, value in (("first", "one"), ("second", "two")):
        assert rule_ctl(
            cmd="add",
            rule={
                "id": rid,
                "filter": f"~u 127.0.0.1:{_SERVER_PORT}/hdr",
                "phase": "request",
                "actions": [
                    {
                        "type": "set_header",
                        "target": "request",
                        "name": "X-Mark",
                        "value": value,
                    }
                ],
            },
        )["success"] is True

    _get_via_proxy(f"http://127.0.0.1:{_SERVER_PORT}/hdr", proxy_port)

    flow = _latest_flow("/hdr")
    assert _headers(flow)["x-mark"] == "one"
    assert flow["rules_applied"] == ["first"]
    skipped = flow["rules_skipped"]
    assert [s["rule_id"] for s in skipped] == ["second"]
    assert skipped[0]["claimed_by"] == "first"
    assert skipped[0]["reason"] == "field_already_claimed"


@pytest.mark.integration
def test_disabling_the_first_rule_lets_the_second_win(proxy) -> None:
    proxy_port = proxy
    for rid, value in (("first", "one"), ("second", "two")):
        rule_ctl(
            cmd="add",
            rule={
                "id": rid,
                "filter": f"~u 127.0.0.1:{_SERVER_PORT}/flip",
                "phase": "request",
                "actions": [
                    {
                        "type": "set_header",
                        "target": "request",
                        "name": "X-Mark",
                        "value": value,
                    }
                ],
            },
        )
    assert rule_ctl(cmd="disable", rule_id="first")["success"] is True

    _get_via_proxy(f"http://127.0.0.1:{_SERVER_PORT}/flip", proxy_port)
    flow = _latest_flow("/flip")
    assert _headers(flow)["x-mark"] == "two"
    assert flow["rules_applied"] == ["second"]
    assert flow["rules_skipped"] == []


@pytest.mark.integration
def test_ruleset_master_switch_gates_live_rewrites(proxy) -> None:
    proxy_port = proxy
    assert rule_ctl(
        cmd="ruleset_add", ruleset={"id": "rs", "name": "rewrite", "enabled": True}
    )["success"] is True
    assert rule_ctl(
        cmd="ruleset_add_rule",
        ruleset_id="rs",
        rule={
            "id": "in-set",
            "filter": f"~u 127.0.0.1:{_SERVER_PORT}/set",
            "phase": "request",
            "actions": [
                {
                    "type": "set_header",
                    "target": "request",
                    "name": "X-Set",
                    "value": "yes",
                }
            ],
        },
    )["success"] is True

    _get_via_proxy(f"http://127.0.0.1:{_SERVER_PORT}/set?on=1", proxy_port)
    assert _headers(_latest_flow("/set?on=1"))["x-set"] == "yes"

    assert rule_ctl(cmd="ruleset_disable", ruleset_id="rs")["success"] is True
    _get_via_proxy(f"http://127.0.0.1:{_SERVER_PORT}/set?off=1", proxy_port)
    assert "x-set" not in _headers(_latest_flow("/set?off=1"))


@pytest.mark.integration
def test_set_url_rewrites_the_request_the_origin_receives(proxy) -> None:
    proxy_port = proxy
    assert rule_ctl(
        cmd="add",
        rule={
            "id": "url",
            "filter": f"~u 127.0.0.1:{_SERVER_PORT}/old",
            "phase": "request",
            "actions": [
                {"type": "set_url", "url": f"http://127.0.0.1:{_SERVER_PORT}/new?x=1"}
            ],
        },
    )["success"] is True

    status, payload = _get_via_proxy(f"http://127.0.0.1:{_SERVER_PORT}/old", proxy_port)
    assert status == 200
    assert payload["path"] == "/new?x=1"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-m", "integration", "-v"]))
