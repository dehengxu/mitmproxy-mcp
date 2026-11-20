"""Tests for REQ-6.1: breakpoint three-state decisions and manual hold."""

import asyncio

import pytest
from mitmproxy import http
from mitmproxy.connection import Client, Server

from mitmproxy_mcp.rules import Action, Rule, RulesAddon


def _make_flow(url: str = "http://example.com/", method: str = "GET") -> http.HTTPFlow:
    req = http.Request.make(method, url)
    client = Client(peername=("127.0.0.1", 12345), sockname=("127.0.0.1", 8080))
    server = Server(address=(req.host, req.port))
    flow = http.HTTPFlow(client, server)
    flow.request = req
    flow.id = 7
    return flow


def _run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Hold + pending token
# ---------------------------------------------------------------------------


def test_intercept_holds_flow_and_issues_pending_token() -> None:
    addon = RulesAddon()
    rule = Rule(
        id="bp",
        filter="~u example.com",
        actions=[Action(type="intercept")],
    )
    addon.add_rule(rule)
    flow = _make_flow()

    _run(addon.request(flow))

    assert flow.intercepted is True
    pending = addon.list_pending()
    assert len(pending) == 1
    assert pending[0].flow_id == 7
    assert pending[0].rule_id == "bp"
    assert pending[0].phase == "request"
    assert pending[0].token


def test_no_pending_when_rule_does_not_match() -> None:
    addon = RulesAddon()
    addon.add_rule(
        Rule(id="bp", filter="~u other.com", actions=[Action(type="intercept")])
    )
    flow = _make_flow()

    _run(addon.request(flow))

    assert flow.intercepted is False
    assert addon.list_pending() == []


def test_disabled_rule_does_not_hold() -> None:
    addon = RulesAddon()
    addon.add_rule(
        Rule(
            id="bp",
            filter="~u example.com",
            actions=[Action(type="intercept")],
            enabled=False,
        )
    )
    flow = _make_flow()

    _run(addon.request(flow))

    assert flow.intercepted is False
    assert addon.list_pending() == []


# ---------------------------------------------------------------------------
# The three decisions
# ---------------------------------------------------------------------------


def _hold_flow(addon: RulesAddon, flow: http.HTTPFlow) -> str:
    addon.add_rule(
        Rule(id="bp", filter="~u example.com", actions=[Action(type="intercept")])
    )
    _run(addon.request(flow))
    return addon.list_pending()[0].token


def test_decide_execute_releases_flow() -> None:
    addon = RulesAddon()
    flow = _make_flow()
    token = _hold_flow(addon, flow)

    pending, released = addon.decide(token, "execute")

    assert pending.token == token
    assert released.intercepted is False
    assert flow.metadata["mitmproxy_mcp_decision"] == "execute"
    assert addon.list_pending() == []


def test_decide_abort_kills_flow() -> None:
    addon = RulesAddon()
    flow = _make_flow()
    token = _hold_flow(addon, flow)

    _, released = addon.decide(token, "abort")

    assert released.live is False
    assert flow.metadata["mitmproxy_mcp_decision"] == "abort"
    assert addon.list_pending() == []


def test_decide_cancel_restores_original_request() -> None:
    addon = RulesAddon()
    flow = _make_flow()
    token = _hold_flow(addon, flow)
    original_path = flow.request.path

    # Edit the request while the flow is held.
    flow.request.path = "/edited"
    assert flow.request.path == "/edited"

    _, released = addon.decide(token, "cancel")

    assert released.request.path == original_path
    assert flow.metadata["mitmproxy_mcp_decision"] == "cancel"
    assert flow.intercepted is False
    assert addon.list_pending() == []


def test_decide_unknown_token_raises() -> None:
    addon = RulesAddon()
    with pytest.raises(KeyError):
        addon.decide("nope", "execute")


def test_decide_twice_raises() -> None:
    addon = RulesAddon()
    flow = _make_flow()
    token = _hold_flow(addon, flow)
    addon.decide(token, "execute")
    with pytest.raises(KeyError):
        addon.decide(token, "execute")


# ---------------------------------------------------------------------------
# Rule management used by the three-state flow
# ---------------------------------------------------------------------------


def test_update_rule_changes_decision() -> None:
    addon = RulesAddon()
    addon.add_rule(
        Rule(id="bp", filter="~u example.com", actions=[Action(type="intercept")])
    )

    updated = addon.update_rule("bp", {"decision": "cancel", "name": "checkout"})

    assert updated is not None
    assert updated.decision == "cancel"
    assert updated.name == "checkout"
    assert addon.list_rules()[0].decision == "cancel"


def test_update_rule_validates_filter() -> None:
    addon = RulesAddon()
    addon.add_rule(
        Rule(id="bp", filter="~u example.com", actions=[Action(type="intercept")])
    )

    with pytest.raises(ValueError):
        addon.update_rule("bp", {"filter": "~~~bad"})


def test_cancel_action_is_accepted() -> None:
    action = Action(type="cancel")
    assert action.type == "cancel"
