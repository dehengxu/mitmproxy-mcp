"""End-to-end: a real WebMaster, a real HTTP client, the real /rewrite/* routes.

Run with::

    pytest tests/test_req61_rewrite_web_e2e.py -m integration -v

What this proves that the contract tests cannot: the endpoints are mounted on
the application the proxy itself starts (same process, same origin, same auth
token), and a real request held by a real rule can be listed and decided over
plain HTTP.
"""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

import pytest

from mitmproxy_mcp.server import proxy_ctl, rule_ctl

# This file's own port block, clear of every other test file (18080-18251,
# 19000-19401, 19700-19705) so a full-suite run cannot collide.
_PROXY_PORT = 18601
_WEB_PORT = 18602
_ORIGIN_PORT = 19601


@pytest.fixture(autouse=True)
def _cleanup():
    try:
        proxy_ctl(cmd="stop")
        rule_ctl(cmd="clear")
    except Exception:
        pass
    yield
    try:
        rule_ctl(cmd="clear")
        proxy_ctl(cmd="stop")
    except Exception:
        pass


def _start_origin(port: int) -> subprocess.Popen:
    server = subprocess.Popen(
        [sys.executable, "-m", "http.server", str(port), "--bind", "127.0.0.1"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return server
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("origin server did not start")


class WebApi:
    """Minimal client for the mitmweb origin, auth included."""

    def __init__(self, base: str) -> None:
        self.base = base
        # Both cookies a browser would hold: the auth cookie and the XSRF one.
        self.cookies: dict[str, str] = {}
        self.xsrf: str | None = None

    @property
    def cookie(self) -> str | None:
        """The auth cookie, for assertions about the login step."""
        for name, value in self.cookies.items():
            if name.startswith("mitmproxy-auth-"):
                return f"{name}={value}"
        return None

    def _request(self, path: str, data: dict | None = None) -> tuple[int, dict]:
        url = self.base + path
        headers = {}
        body = None
        if data is not None:
            body = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
            if self.xsrf:
                headers["X-XSRFToken"] = self.xsrf
        if self.cookies:
            headers["Cookie"] = "; ".join(
                f"{name}={value}" for name, value in self.cookies.items()
            )
        request = urllib.request.Request(url, data=body, headers=headers, method="GET" if data is None else "POST")
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                payload = json.loads(response.read().decode() or "{}")
                self._absorb_cookies(response.headers.get_all("Set-Cookie") or [])
                return response.status, payload
        except urllib.error.HTTPError as e:
            return e.code, {"error": e.read().decode(errors="replace")}

    def _absorb_cookies(self, headers: list[str]) -> None:
        for header in headers:
            name, _, rest = header.partition("=")
            value = rest.split(";", 1)[0]
            self.cookies[name] = value
            if name == "_mitmproxy_xsrf":
                self.xsrf = value

    def get(self, path: str) -> tuple[int, dict]:
        return self._request(path)

    def post(self, path: str, data: dict) -> tuple[int, dict]:
        return self._request(path, data)


def _wait_pending(api: WebApi, timeout: float = 15.0) -> list[dict]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        status, data = api.get("/rewrite/pending")
        assert status == 200, data
        if data.get("pending"):
            return data["pending"]
        time.sleep(0.2)
    return []


@pytest.mark.integration
def test_webmaster_serves_rewrite_endpoints_on_its_own_origin() -> None:
    origin = _start_origin(_ORIGIN_PORT)
    try:
        start = proxy_ctl(
            cmd="start", port=_PROXY_PORT, webui=True, web_port=_WEB_PORT
        )
        assert start["success"] is True, start
        web_url = start["web_url"]
        assert f":{_WEB_PORT}" in web_url
        token = web_url.split("token=", 1)[1]
        base = web_url.split("?", 1)[0].rstrip("/")

        api = WebApi(base)
        # The web server binds shortly after start() returns; wait for it.
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", _WEB_PORT), timeout=0.5):
                    break
            except OSError:
                time.sleep(0.15)
        # Logging in with the startup token sets the auth cookie.
        status, _ = api.get(f"/rewrite/pending?token={token}")
        assert status == 200
        assert api.cookie, "the token login must hand out the auth cookie"

        # 1) rules: add, list, enable, delete over HTTP only.
        status, body = api.post(
            "/rewrite/rules",
            {
                "id": "bp",
                "name": "Breakpoint",
                "filter": f"~u 127.0.0.1:{_ORIGIN_PORT}",
                "phase": "request",
                "actions": [{"type": "intercept"}],
            },
        )
        assert status == 200 and body["success"] is True, body

        status, body = api.get("/rewrite/rules")
        assert status == 200
        assert [r["id"] for r in body["rules"]] == ["bp"]
        assert body["rulesets"] == []

        status, body = api.post(
            "/rewrite/rules/enable", {"id": "bp", "enabled": False}
        )
        assert body["success"] is True and body["rule"]["enabled"] is False
        status, body = api.get("/rewrite/rules")
        assert body["rules"][0]["enabled"] is False
        # Turn it back on: the hold below needs it.
        api.post("/rewrite/rules/enable", {"id": "bp", "enabled": True})

        # 2) pending: a real client request is held by the real rule.
        result: dict = {}

        def _fetch() -> None:
            handler = urllib.request.ProxyHandler(
                {"http": f"http://127.0.0.1:{_PROXY_PORT}"}
            )
            opener = urllib.request.build_opener(handler)
            try:
                with opener.open(
                    f"http://127.0.0.1:{_ORIGIN_PORT}/", timeout=25
                ) as response:
                    result["status"] = response.status
            except urllib.error.HTTPError as e:
                result["status"] = e.code
            except Exception as e:  # noqa: BLE001
                result["error"] = repr(e)

        thread = threading.Thread(target=_fetch, daemon=True)
        thread.start()

        pending = _wait_pending(api)
        assert pending, "the flow was never held"
        entry = pending[0]
        assert entry["rule_id"] == "bp"
        assert entry["rule_name"] == "Breakpoint"
        assert entry["phase"] == "request"
        assert entry["path"] == "/"
        assert entry["host"] == "127.0.0.1"
        assert entry["method"] == "GET"
        assert isinstance(entry["created_at"], int)

        # 3) decide: execute releases the flow and the client gets its answer.
        status, body = api.post(
            "/rewrite/pending/decide",
            {"token": entry["token"], "decision": "execute"},
        )
        assert status == 200 and body["success"] is True, body
        thread.join(timeout=15)
        assert result.get("status") == 200, result

        status, body = api.get("/rewrite/pending")
        assert body["pending"] == []

        # 4) deciding the same token again is an in-band failure, not a 200 lie.
        status, body = api.post(
            "/rewrite/pending/decide",
            {"token": entry["token"], "decision": "execute"},
        )
        assert status == 200
        assert body["success"] is False
        assert "token" in body["error"].lower()

        # 5) delete over HTTP.
        status, body = api.post("/rewrite/rules/delete", {"id": "bp"})
        assert body["success"] is True
        status, body = api.get("/rewrite/rules")
        assert body["rules"] == []
    finally:
        origin.terminate()
        origin.wait(timeout=5)


@pytest.mark.integration
def test_without_webui_there_are_no_rewrite_routes() -> None:
    """webui=False runs a DumpMaster: the MCP tools stay the only entry point."""
    start = proxy_ctl(cmd="start", port=_PROXY_PORT + 10)
    assert start["success"] is True, start
    assert start["webui"] is False
    # No http port is exposed at all, so there is nothing to mount on.
    assert "web_url" not in start
    from mitmproxy.tools.dump import DumpMaster

    from mitmproxy_mcp.server import proxy_manager

    assert isinstance(proxy_manager._master, DumpMaster)
    assert not hasattr(proxy_manager._master, "app")
