"""REQ-6.1 follow-up, end to end: a real proxy, a real client, a real origin.

Three claims from the acceptance criteria, each checked against real sockets
rather than a hand-made flow:

a. a client that hangs up while its flow is held disappears from
   ``GET /rewrite/pending`` within two seconds;
b. a hold that outlives the TTL vanishes from the queue, the origin receives
   nothing, and the client connection is closed (not left hanging);
c. deciding an expired token answers ``success: false`` with the expiry
   message.

The TTL is injected short here (the production value, asserted in
``test_req61_pending_cleanup.py``, is 300 s); everything else -- ports, proxy,
rule engine, HTTP layer -- is the production path.

Run with::

    pytest tests/test_req61_pending_cleanup_e2e.py -m integration -v
"""

from __future__ import annotations

import socket
import threading
import time

import pytest

from mitmproxy_mcp.server import proxy_ctl, proxy_manager, rule_ctl

# This file's own block, clear of every other test file (18080-18261,
# 18601-18602, 19000-19741).
# One port triple per test. A proxy that has just been stopped can hold its
# listening socket for a moment, and a just-closed origin keeps accepted
# connections in TIME_WAIT; giving every test its own triple keeps the three
# cases independent instead of making one depend on the last one's teardown.
_PORT_SETS = (
    {"proxy": 18701, "web": 18702, "origin": 19741},
    {"proxy": 18711, "web": 18712, "origin": 19742},
    {"proxy": 18721, "web": 18722, "origin": 19743},
)
_port_set_index = {"n": 0}


def _next_ports() -> dict[str, int]:
    ports = _PORT_SETS[_port_set_index["n"] % len(_PORT_SETS)]
    _port_set_index["n"] += 1
    return ports

_FAST_TTL = 3


@pytest.fixture(autouse=True)
def _cleanup():
    try:
        proxy_ctl(cmd="stop")
        rule_ctl(cmd="clear")
    except Exception:
        pass
    try:
        proxy_manager.rules_addon.set_pending_ttl(300)
    except Exception:
        pass
    yield
    try:
        rule_ctl(cmd="clear")
        proxy_ctl(cmd="stop")
        proxy_manager.rules_addon.set_pending_ttl(300)
    except Exception:
        pass


class _Origin:
    """A counting origin: every accepted request increments ``hits``."""

    def __init__(self, port: int) -> None:
        self.hits = 0
        self.lock = threading.Lock()
        self._stop = threading.Event()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", port))
        self._sock.listen(16)
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()
            except OSError:
                return
            with conn:
                try:
                    conn.recv(65536)
                except OSError:
                    pass
                with self.lock:
                    self.hits += 1
                body = b"origin-ok"
                try:
                    conn.sendall(
                        b"HTTP/1.1 200 OK\r\nContent-Length: "
                        + str(len(body)).encode()
                        + b"\r\nConnection: close\r\n\r\n"
                        + body
                    )
                except OSError:
                    pass

    def __enter__(self) -> "_Origin":
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=5)


def _start_proxy(ports: dict[str, int]) -> None:
    start = proxy_ctl(
        cmd="start", port=ports["proxy"], webui=True, web_port=ports["web"]
    )
    assert start["success"] is True, start
    deadline = time.time() + 15
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", ports["web"]), timeout=0.5):
                return
        except OSError:
            time.sleep(0.1)


def _hold_rule(origin_port: int, path_prefix: str = "/api") -> None:
    result = rule_ctl(
        cmd="add",
        rule={
            "id": "bp",
            "name": "Breakpoint",
            "filter": f"~u 127.0.0.1:{origin_port}{path_prefix}",
            "phase": "request",
            "actions": [{"type": "intercept"}],
        },
    )
    assert result["success"] is True, result


def _pending() -> list[dict]:
    result = rule_ctl(cmd="pending")
    assert result["success"] is True, result
    return result["pending"]


def _wait_pending(timeout: float = 10.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        entries = _pending()
        if entries:
            return entries[0]
        time.sleep(0.1)
    raise AssertionError("the request was never held for a decision")


def _open_held_request(
    proxy_port: int, origin_port: int, path: str = "/api"
) -> socket.socket:
    """Send one request through the proxy and leave the socket open."""
    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=30)
    sock.sendall(
        (
            f"GET http://127.0.0.1:{origin_port}{path} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{origin_port}\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
    )
    return sock


def _read_until_closed(sock: socket.socket, timeout: float = 10.0) -> tuple[bytes, float]:
    sock.settimeout(timeout)
    started = time.time()
    data = b""
    while True:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
    return data, time.time() - started


@pytest.mark.integration
def test_killed_client_leaves_the_pending_queue_within_two_seconds() -> None:
    """(a) Hanging up while held must clear the row, fast."""
    ports = _next_ports()
    with _Origin(ports["origin"]) as origin:
        _start_proxy(ports)
        _hold_rule(ports["origin"])

        sock = _open_held_request(ports["proxy"], ports["origin"])
        entry = _wait_pending()
        token = entry["token"]
        assert [e["token"] for e in _pending()] == [token]

        # The client gives up while the flow is held.
        sock.close()
        closed_at = time.time()

        removed_after = None
        deadline = time.time() + 5
        while time.time() < deadline:
            if token not in [e["token"] for e in _pending()]:
                removed_after = time.time() - closed_at
                break
            time.sleep(0.1)

        assert removed_after is not None, "the row outlived its disconnected client"
        assert removed_after <= 2.0, f"took {removed_after:.2f}s to clear"
        assert origin.hits == 0, "the abandoned request must never reach the origin"

        result = rule_ctl(cmd="decide", token=token, decision="abort")
        assert result["success"] is False
        assert result["error"] == "客户端已断开，待决策已取消"


@pytest.mark.integration
def test_hold_past_the_ttl_is_dropped_closed_and_never_forwarded() -> None:
    """(b) TTL: entry gone, origin untouched, client connection closed."""
    ports = _next_ports()
    with _Origin(ports["origin"]) as origin:
        _start_proxy(ports)
        _hold_rule(ports["origin"])
        # Test-only injection: 3 seconds instead of the production 300.
        proxy_manager.rules_addon.set_pending_ttl(_FAST_TTL)
        assert proxy_manager.rules_addon.pending_ttl() == _FAST_TTL

        sock = _open_held_request(ports["proxy"], ports["origin"])
        entry = _wait_pending()
        token = entry["token"]
        # The panel counts down from expire_at, which must honour the TTL.
        assert entry["expire_at"] - entry["created_at"] == _FAST_TTL

        data, elapsed = _read_until_closed(sock, timeout=_FAST_TTL + 8)
        sock.close()

        assert data == b"", f"the client must get no response, got {data!r}"
        assert elapsed <= _FAST_TTL + 5, f"the connection stayed open {elapsed:.1f}s"
        assert _pending() == [], "the expired hold must leave the queue"
        assert origin.hits == 0, "an expired request must never reach the origin"
        assert entry["token"] == token


@pytest.mark.integration
def test_deciding_an_expired_token_says_so() -> None:
    """(c) A late decide() is an in-band failure with the expiry message."""
    ports = _next_ports()
    with _Origin(ports["origin"]) as origin:
        _start_proxy(ports)
        _hold_rule(ports["origin"])
        proxy_manager.rules_addon.set_pending_ttl(_FAST_TTL)

        sock = _open_held_request(ports["proxy"], ports["origin"])
        entry = _wait_pending()
        token = entry["token"]
        _read_until_closed(sock, timeout=_FAST_TTL + 8)
        sock.close()
        assert _pending() == []

        result = rule_ctl(cmd="decide", token=token, decision="execute")
        assert result["success"] is False
        assert result["error"] == "待决策已过期（TTL 5 分钟），已自动清理"
        assert origin.hits == 0
