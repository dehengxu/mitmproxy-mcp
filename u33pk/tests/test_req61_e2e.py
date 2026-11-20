"""End-to-end tests for REQ-6.1: a real proxy, real HTTP, real three-state decision.

These exercise the full path that unit tests cannot: mitmproxy assigns
flow.id as a UUID string, and a real client socket is held open until a
decision arrives. Unit tests with a hand-made flow hid a real type bug
(PendingDecision.flow_id was int, mitmproxy's flow.id is a UUID string), so
the hold silently failed and the request was released without a decision.

Run with:

    pytest tests/test_req61_e2e.py -m integration -v
"""

from __future__ import annotations

import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

import pytest

from mitmproxy_mcp.server import http_ctl, proxy_ctl, rule_ctl


@pytest.fixture(autouse=True)
def _cleanup():
    try:
        proxy_ctl(cmd="stop")
        rule_ctl(cmd="clear")
        http_ctl(cmd="clear")
    except Exception:
        pass
    yield
    try:
        rule_ctl(cmd="clear")
        http_ctl(cmd="clear")
        proxy_ctl(cmd="stop")
    except Exception:
        pass


# Fixed, non-overlapping port blocks for this file. Other test files use
# 18080-18164 and 19700-19705; these stay clear of them.
_SERVER_PORTS = (19201, 19202, 19203)
_PROXY_PORTS = (18201, 18202, 18203)
_port_index = {"n": 0}


def _free_port() -> int:
    """Hand out the next port from this file's reserved block."""
    i = _port_index["n"]
    _port_index["n"] += 1
    return _SERVER_PORTS[i] if i < len(_SERVER_PORTS) else _PROXY_PORTS[i - len(_SERVER_PORTS)]


def _start_http_server(port: int) -> subprocess.Popen:
    server = subprocess.Popen(
        [sys.executable, "-m", "http.server", str(port), "--bind", "127.0.0.1"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1)
    return server


def _get_via_proxy(url: str, proxy_port: int, timeout: float = 10):
    proxy_handler = urllib.request.ProxyHandler(
        {"http": f"http://127.0.0.1:{proxy_port}"}
    )
    opener = urllib.request.build_opener(proxy_handler)
    try:
        with opener.open(urllib.request.Request(url, method="GET"), timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def _wait_for_pending(timeout: float = 10.0) -> list[dict]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        pending = rule_ctl(cmd="pending").get("pending", [])
        if pending:
            return pending
        time.sleep(0.2)
    return []


@pytest.mark.integration
def test_intercept_holds_real_request_until_decided() -> None:
    """A real client request must stay open until a decision arrives."""
    server_port = _free_port()
    proxy_port = _free_port()
    server = _start_http_server(server_port)
    try:
        r = proxy_ctl(cmd="start", port=proxy_port)
        assert r["success"] is True

        r = rule_ctl(
            cmd="add",
            rule={
                "id": "bp",
                "filter": f"~u 127.0.0.1:{server_port}/api",
                "phase": "request",
                "actions": [{"type": "intercept"}],
            },
        )
        assert r["success"] is True

        result: dict = {}

        import threading

        def _fetch():
            try:
                result["status"] = _get_via_proxy(
                    f"http://127.0.0.1:{server_port}/api", proxy_port, timeout=20
                )
            except Exception as e:  # noqa: BLE001
                result["error"] = repr(e)

        t = threading.Thread(target=_fetch, daemon=True)
        t.start()

        pending = _wait_for_pending()
        assert pending, "the request was never held for a decision"
        entry = pending[0]
        # mitmproxy's native flow id is a UUID string.
        assert isinstance(entry["flow_id"], str)
        assert entry["rule_id"] == "bp"
        assert entry["phase"] == "request"

        # While held, the client must still be waiting.
        t.join(timeout=2)
        assert t.is_alive(), "the request was released before a decision"

        r = rule_ctl(cmd="decide", token=entry["token"], decision="execute")
        assert r["success"] is True

        t.join(timeout=20)
        assert not t.is_alive()
        assert result.get("status") == 404, result
    finally:
        server.terminate()


@pytest.mark.integration
def test_cancel_releases_request_unchanged() -> None:
    """Cancel must release the held request so the client gets its response."""
    server_port = _free_port()
    proxy_port = _free_port()
    server = _start_http_server(server_port)
    try:
        assert proxy_ctl(cmd="start", port=proxy_port)["success"] is True
        assert rule_ctl(
            cmd="add",
            rule={
                "id": "bp",
                "filter": f"~u 127.0.0.1:{server_port}/api",
                "phase": "request",
                "actions": [{"type": "intercept"}],
            },
        )["success"] is True

        result: dict = {}
        import threading

        def _fetch():
            try:
                result["status"] = _get_via_proxy(
                    f"http://127.0.0.1:{server_port}/api", proxy_port, timeout=20
                )
            except Exception as e:  # noqa: BLE001
                result["error"] = repr(e)

        t = threading.Thread(target=_fetch, daemon=True)
        t.start()

        pending = _wait_for_pending()
        assert pending, "the request was never held for a decision"

        r = rule_ctl(cmd="decide", token=pending[0]["token"], decision="cancel")
        assert r["success"] is True

        t.join(timeout=20)
        assert not t.is_alive()
        assert result.get("status") == 404, result
    finally:
        server.terminate()


@pytest.mark.integration
def test_abort_kills_request() -> None:
    """Abort must terminate the request; the client must not get a response."""
    server_port = _free_port()
    proxy_port = _free_port()
    server = _start_http_server(server_port)
    try:
        assert proxy_ctl(cmd="start", port=proxy_port)["success"] is True
        assert rule_ctl(
            cmd="add",
            rule={
                "id": "bp",
                "filter": f"~u 127.0.0.1:{server_port}/api",
                "phase": "request",
                "actions": [{"type": "intercept"}],
            },
        )["success"] is True

        result: dict = {}
        import threading

        def _fetch():
            try:
                result["status"] = _get_via_proxy(
                    f"http://127.0.0.1:{server_port}/api", proxy_port, timeout=20
                )
            except Exception as e:  # noqa: BLE001
                result["error"] = repr(e)

        t = threading.Thread(target=_fetch, daemon=True)
        t.start()

        pending = _wait_for_pending()
        assert pending, "the request was never held for a decision"

        r = rule_ctl(cmd="decide", token=pending[0]["token"], decision="abort")
        assert r["success"] is True

        t.join(timeout=20)
        assert not t.is_alive()
        # Abort must not deliver the origin's response.
        assert result.get("status") != 404, result
    finally:
        server.terminate()
