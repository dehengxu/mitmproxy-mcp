"""REQ-6.2: set_query / remove_query / set_url action semantics."""

from __future__ import annotations

import asyncio
from urllib.parse import parse_qsl, urlsplit

import pytest
from mitmproxy import http
from mitmproxy.connection import Client, Server

from mitmproxy_mcp.rules import Action, Rule, RulesAddon, action_claims


def _make_flow(url: str = "http://example.com/") -> http.HTTPFlow:
    req = http.Request.make("GET", url)
    client = Client(peername=("127.0.0.1", 12345), sockname=("127.0.0.1", 8080))
    server = Server(address=(req.host, req.port))
    flow = http.HTTPFlow(client, server)
    flow.request = req
    return flow


def _run(coro):
    return asyncio.run(coro)


def _addon_with(actions: list[Action], rule_id: str = "r1") -> RulesAddon:
    addon = RulesAddon()
    addon.add_rule(
        Rule(id=rule_id, filter="~u example.com", phase="request", actions=actions)
    )
    return addon


# ---------------------------------------------------------------------------
# set_query
# ---------------------------------------------------------------------------


def test_set_query_adds_a_parameter() -> None:
    addon = _addon_with([Action(type="set_query", name="page", value="2")])
    flow = _make_flow("http://example.com/list?sort=asc")
    _run(addon.request(flow))
    assert dict(parse_qsl(urlsplit(flow.request.url).query)) == {
        "sort": "asc",
        "page": "2",
    }


def test_set_query_overwrites_existing_parameter() -> None:
    addon = _addon_with([Action(type="set_query", name="page", value="9")])
    flow = _make_flow("http://example.com/list?page=1")
    _run(addon.request(flow))
    assert flow.request.query["page"] == "9"


def test_set_query_replaces_all_duplicate_values() -> None:
    """A repeated parameter collapses to the single configured value."""
    addon = _addon_with([Action(type="set_query", name="tag", value="x")])
    flow = _make_flow("http://example.com/list?tag=a&tag=b")
    _run(addon.request(flow))
    assert flow.request.query.get_all("tag") == ["x"]


def test_set_query_url_encodes_name_and_value() -> None:
    """Special characters must be encoded, never spliced into the URL by hand."""
    addon = _addon_with(
        [Action(type="set_query", name="q", value="a b&c=d+e/f?g#h 中文")]
    )
    flow = _make_flow("http://example.com/search")
    _run(addon.request(flow))
    # Round-trips through the URL: nothing was lost and nothing was misparsed.
    assert dict(parse_qsl(urlsplit(flow.request.url).query))["q"] == (
        "a b&c=d+e/f?g#h 中文"
    )
    # An unencoded '&' would have split the value into extra parameters.
    assert len(parse_qsl(urlsplit(flow.request.url).query)) == 1


def test_set_query_keeps_fragment_and_path() -> None:
    addon = _addon_with([Action(type="set_query", name="k", value="v")])
    flow = _make_flow("http://example.com/a/b?old=1")
    _run(addon.request(flow))
    assert flow.request.path.startswith("/a/b?")


def test_set_query_requires_name_and_value() -> None:
    with pytest.raises(ValueError):
        Action(type="set_query", value="1")
    with pytest.raises(ValueError):
        Action(type="set_query", name="a")


def test_set_query_rejects_response_target() -> None:
    """Query belongs to the request; a response target is a config error."""
    with pytest.raises(ValueError):
        Action(type="set_query", target="response", name="a", value="1")


def test_set_query_accepts_explicit_request_target() -> None:
    action = Action(type="set_query", target="request", name="a", value="1")
    assert action.target == "request"


# ---------------------------------------------------------------------------
# remove_query
# ---------------------------------------------------------------------------


def test_remove_query_drops_parameter() -> None:
    addon = _addon_with([Action(type="remove_query", name="debug")])
    flow = _make_flow("http://example.com/x?debug=1&keep=2")
    _run(addon.request(flow))
    assert "debug" not in flow.request.query
    assert flow.request.query["keep"] == "2"


def test_remove_query_absent_is_a_no_op() -> None:
    addon = _addon_with([Action(type="remove_query", name="nope")])
    flow = _make_flow("http://example.com/x?a=1")
    _run(addon.request(flow))
    assert flow.request.path == "/x?a=1"


def test_remove_query_requires_name() -> None:
    with pytest.raises(ValueError):
        Action(type="remove_query")


# ---------------------------------------------------------------------------
# set_url
# ---------------------------------------------------------------------------


def test_set_url_replaces_scheme_host_port_path_and_query() -> None:
    addon = _addon_with([Action(type="set_url", url="https://other.example.org:8443/v2/x?a=1")])
    flow = _make_flow("http://example.com/original?old=1")
    _run(addon.request(flow))
    req = flow.request
    assert req.scheme == "https"
    assert req.host == "other.example.org"
    assert req.port == 8443
    assert req.path == "/v2/x?a=1"


def test_set_url_encodes_special_characters() -> None:
    addon = _addon_with(
        [Action(type="set_url", url="http://example.com/p?q=a%20b&r=%E4%B8%AD")]
    )
    flow = _make_flow("http://example.com/")
    _run(addon.request(flow))
    assert dict(parse_qsl(urlsplit(flow.request.url).query)) == {"q": "a b", "r": "中"}


def test_set_url_requires_an_absolute_url() -> None:
    with pytest.raises(ValueError):
        Action(type="set_url", url="/only/a/path")
    with pytest.raises(ValueError):
        Action(type="set_url")


# ---------------------------------------------------------------------------
# Conflict claims
# ---------------------------------------------------------------------------


def test_query_claims_are_per_parameter() -> None:
    a = action_claims(Action(type="set_query", name="a", value="1"))
    b = action_claims(Action(type="set_query", name="b", value="2"))
    assert a == [("request", "query:a")]
    assert a != b


def test_set_url_claims_url_path_and_every_query() -> None:
    claims = action_claims(Action(type="set_url", url="http://e.com/x"))
    assert ("request", "url") in claims
    assert ("request", "path") in claims
    assert ("request", "query:*") in claims


def test_control_actions_claim_nothing() -> None:
    for t in ("kill", "intercept", "resume", "cancel", "delay", "mark", "comment", "tag"):
        kwargs = {}
        if t == "delay":
            kwargs["seconds"] = 0
        if t == "mark":
            kwargs["marker"] = "m"
        if t == "comment":
            kwargs["comment"] = "c"
        if t == "tag":
            kwargs["tags"] = ["t"]
        assert action_claims(Action(type=t, **kwargs)) == []
