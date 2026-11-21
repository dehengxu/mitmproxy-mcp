"""REQ-6.1 follow-up: the pending queue clears itself.

The acceptance line is "the pending token expires or the client disconnects,
and the queue clears itself". Before this, ``_pending`` was only emptied by
``decide()``: an abandoned hold stayed in ``GET /rewrite/pending`` and in the
WebUI panel forever, and the client connection stayed open with nothing left
to release it.

Covered here, without a proxy:

* each listed entry carries ``expire_at`` and ``state`` (the frozen contract
  the WebUI counts down from);
* an entry past its TTL is dropped, the flow is killed and woken in one go,
  and ``decide()`` afterwards answers with the expired message;
* ``client_disconnected`` drops the entry immediately, for that connection
  only;
* the ``error`` hook is the safety net for a client that vanished without the
  hook, and does not touch a healthy hold;
* the background reaper sweeps on its own, without anyone reading the list;
* the "why did it leave" memory is bounded.
"""

from __future__ import annotations

import asyncio
import time

import pytest
from mitmproxy import http
from mitmproxy.connection import Client, ConnectionState, Server

from mitmproxy_mcp.rules import (
    PENDING_CLIENT_DISCONNECTED_MESSAGE,
    PENDING_EXPIRED_MESSAGE,
    PENDING_TTL_SECONDS,
    Action,
    PendingGone,
    Rule,
    RulesAddon,
)
from mitmproxy_mcp.rewrite_web import _pending_payload


def _make_flow(url: str = "http://example.com/api", live: bool = False) -> http.HTTPFlow:
    req = http.Request.make("GET", url)
    client = Client(
        peername=("127.0.0.1", 50000),
        sockname=("127.0.0.1", 8080),
        state=ConnectionState.OPEN,
    )
    server = Server(address=(req.host, req.port))
    flow = http.HTTPFlow(client, server)
    flow.request = req
    flow.live = live
    return flow


class _Recorder:
    """A FlowController that records what the engine asked it to do."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, http.HTTPFlow]] = []

    def resume(self, flow: http.HTTPFlow) -> None:
        self.calls.append(("resume", flow))

    def kill(self, flow: http.HTTPFlow) -> None:
        self.calls.append(("kill", flow))

    def kill_and_wake(self, flow: http.HTTPFlow) -> None:
        self.calls.append(("kill_and_wake", flow))


def _holding_addon(**kwargs) -> tuple[RulesAddon, _Recorder, http.HTTPFlow, str]:
    recorder = _Recorder()
    addon = RulesAddon(flow_controller=recorder, **kwargs)
    addon.add_rule(
        Rule(id="bp", filter="~u example.com", actions=[Action(type="intercept")])
    )
    flow = _make_flow()
    asyncio.run(addon.request(flow))
    assert flow.intercepted is True
    pending = addon.list_pending()
    assert len(pending) == 1
    return addon, recorder, flow, pending[0].token


def test_production_ttl_is_five_minutes() -> None:
    """The acceptance number, not a test value: 300 seconds."""
    assert PENDING_TTL_SECONDS == 300
    assert RulesAddon().pending_ttl() == 300


def test_entry_carries_expire_at_and_state() -> None:
    addon, _recorder, _flow, token = _holding_addon(start_reaper=False)
    entry = addon.list_pending()[0]
    try:
        assert entry.token == token
        assert entry.state == "pending"
        assert entry.expire_at == entry.created_at + PENDING_TTL_SECONDS
        # The payload the WebUI reads has both, as integers.
        payload = _pending_payload(_manager_for(addon))
        assert payload == [
            {
                "token": token,
                "flow_id": entry.flow_id,
                "store_id": None,
                "rule_id": "bp",
                "rule_name": "",
                "phase": "request",
                "host": "example.com",
                "path": "/api",
                "method": "GET",
                "created_at": entry.created_at,
                "expire_at": entry.expire_at,
                "state": "pending",
            }
        ]
        assert isinstance(payload[0]["expire_at"], int)
    finally:
        addon.stop_reaper()


def _manager_for(addon: RulesAddon):
    """A stand-in manager: ``_pending_payload`` only asks for the list."""

    class _Manager:
        def list_pending_decisions(self):
            return addon.list_pending()

    return _Manager()


def test_expired_entry_is_swept_and_reports_expiry() -> None:
    """Past the TTL: gone from the list, flow killed, decide() says expired."""
    addon, recorder, flow, token = _holding_addon(pending_ttl=1, start_reaper=False)
    try:
        assert addon.list_pending(), "the hold must be listed before its TTL"
        time.sleep(1.1)
        assert addon.list_pending() == []
        # Killing and waking in one step is what closes the client connection
        # instead of leaving it parked until its own timeout.
        assert recorder.calls == [("kill_and_wake", flow)]
        assert flow.metadata["mitmproxy_mcp_decision"] == "expired"
        assert addon.removed_reason(token) == "expired"
        with pytest.raises(PendingGone) as err:
            addon.decide(token, "execute")
        assert str(err.value) == PENDING_EXPIRED_MESSAGE
    finally:
        addon.stop_reaper()


def test_lazy_sweep_needs_no_reaper_thread() -> None:
    """Reading the queue is enough: the panel never shows a stale hold."""
    addon, recorder, flow, _token = _holding_addon(pending_ttl=1, start_reaper=False)
    time.sleep(1.1)
    assert addon.list_pending() == []
    assert recorder.calls == [("kill_and_wake", flow)]
    assert addon._reaper_thread is None


def test_reaper_sweeps_without_any_read() -> None:
    """The background reaper clears the queue on its own."""
    addon, recorder, flow, token = _holding_addon(
        pending_ttl=1, reaper_interval=0.2
    )
    try:
        deadline = time.time() + 4
        while time.time() < deadline and addon._pending:
            time.sleep(0.1)
        assert addon._pending == {}, "the reaper must clear an expired hold"
        assert recorder.calls == [("kill_and_wake", flow)]
        assert addon.removed_reason(token) == "expired"
    finally:
        addon.stop_reaper()


def test_client_disconnected_drops_the_entry_at_once() -> None:
    addon, recorder, flow, token = _holding_addon(start_reaper=False)
    try:
        addon.client_disconnected(flow.client_conn)
        assert addon.list_pending() == []
        assert recorder.calls == [("kill_and_wake", flow)]
        assert flow.metadata["mitmproxy_mcp_decision"] == "client_disconnected"
        with pytest.raises(PendingGone) as err:
            addon.decide(token, "cancel")
        assert str(err.value) == PENDING_CLIENT_DISCONNECTED_MESSAGE
    finally:
        addon.stop_reaper()


def test_client_disconnected_ignores_other_connections() -> None:
    addon, recorder, _flow, _token = _holding_addon(start_reaper=False)
    try:
        other = Client(peername=("127.0.0.1", 50001), sockname=("127.0.0.1", 8080))
        addon.client_disconnected(other)
        assert len(addon.list_pending()) == 1
        assert recorder.calls == []
    finally:
        addon.stop_reaper()


def test_client_disconnected_hook_accepts_a_bare_client() -> None:
    """The hook is called with mitmproxy's Client; an unknown id is a no-op."""
    addon, recorder, _flow, _token = _holding_addon(start_reaper=False)
    try:
        addon.client_disconnected(None)  # type: ignore[arg-type]
        assert len(addon.list_pending()) == 1
        assert recorder.calls == []
    finally:
        addon.stop_reaper()


def test_error_hook_is_the_safety_net_for_a_vanished_client() -> None:
    """If ``client_disconnected`` never fired, a dead client is still cleaned."""
    addon, recorder, flow, token = _holding_addon(start_reaper=False)
    try:
        flow.live = True
        flow.client_conn.state = ConnectionState.CAN_WRITE  # peer stopped reading
        addon.error(flow)
        assert addon.list_pending() == []
        assert recorder.calls == [("kill_and_wake", flow)]
        assert addon.removed_reason(token) == "client_disconnected"
    finally:
        addon.stop_reaper()


def test_error_hook_leaves_a_healthy_hold_alone() -> None:
    """A failed upstream connection is not a reason to drop the decision."""
    addon, recorder, flow, _token = _holding_addon(start_reaper=False)
    try:
        flow.live = True
        flow.client_conn.state = ConnectionState.OPEN
        addon.error(flow)
        assert len(addon.list_pending()) == 1
        assert recorder.calls == []
    finally:
        addon.stop_reaper()


def test_decide_still_wins_the_race_against_a_sweep() -> None:
    """decide() pops first, so a sweep never kills a decided flow twice."""
    addon, recorder, flow, token = _holding_addon(start_reaper=False)
    try:
        addon.decide(token, "cancel")
        assert recorder.calls == [("resume", flow)]
        # A later sweep has nothing to do and must not kill the flow.
        addon._sweep_pending()
        assert recorder.calls == [("resume", flow)]
    finally:
        addon.stop_reaper()


def test_removed_reason_memory_is_bounded() -> None:
    addon = RulesAddon(start_reaper=False)
    try:
        for i in range(200):
            addon._remember_removed(f"t{i}", "expired")
        assert len(addon._removed) == 64
        # The newest survive, the oldest are forgotten (they answer the old
        # "No pending decision" wording, which is no worse than before).
        assert addon.removed_reason("t199") == "expired"
        assert addon.removed_reason("t0") is None
    finally:
        addon.stop_reaper()


def test_set_pending_ttl_rejects_a_non_positive_value() -> None:
    addon = RulesAddon(start_reaper=False)
    try:
        with pytest.raises(ValueError):
            addon.set_pending_ttl(0)
        addon.set_pending_ttl(7)
        assert addon.pending_ttl() == 7
    finally:
        addon.stop_reaper()
