"""REQ-6.2: first match wins, no stacking, and the observable skip record."""

from __future__ import annotations

import asyncio

from mitmproxy import http
from mitmproxy.connection import Client, Server

from mitmproxy_mcp.events import EventBuffer
from mitmproxy_mcp.rules import (
    SKIPPED_KEY,
    SKIP_REASON_FIELD_CLAIMED,
    Action,
    Rule,
    RuleSet,
    RulesAddon,
)


def _make_flow(url: str = "http://example.com/") -> http.HTTPFlow:
    req = http.Request.make("GET", url)
    client = Client(peername=("127.0.0.1", 12345), sockname=("127.0.0.1", 8080))
    server = Server(address=(req.host, req.port))
    flow = http.HTTPFlow(client, server)
    flow.request = req
    return flow


def _make_response(flow: http.HTTPFlow) -> None:
    flow.response = http.Response.make(200, content=b"OK")


def _run(coro):
    return asyncio.run(coro)


def _rule(rule_id: str, actions: list[Action], phase: str = "request", **kwargs) -> Rule:
    kwargs.setdefault("filter", "~u example.com")
    return Rule(id=rule_id, phase=phase, actions=actions, **kwargs)


def _addon(*rules: Rule) -> RulesAddon:
    addon = RulesAddon()
    for rule in rules:
        addon.add_rule(rule)
    return addon


def _set_header(rule_id: str, value: str, name: str = "X-Mark", target: str = "request", **kw) -> Rule:
    return _rule(
        rule_id,
        [Action(type="set_header", target=target, name=name, value=value)],
        **kw,
    )


# ---------------------------------------------------------------------------
# Acceptance: same header, two rules
# ---------------------------------------------------------------------------


def test_second_rule_on_same_header_is_skipped_not_applied() -> None:
    addon = _addon(_set_header("r1", "first"), _set_header("r2", "second"))
    flow = _make_flow()
    _run(addon.request(flow))

    assert flow.request.headers["X-Mark"] == "first"
    assert flow.metadata["mitmproxy_mcp_rules_applied"] == ["r1"]


def test_skip_is_recorded_with_reason_and_field() -> None:
    addon = _addon(_set_header("r1", "first"), _set_header("r2", "second"))
    flow = _make_flow()
    _run(addon.request(flow))

    skipped = flow.metadata[SKIPPED_KEY]
    assert len(skipped) == 1
    record = skipped[0]
    assert record["rule_id"] == "r2"
    assert record["action_type"] == "set_header"
    assert record["reason"] == SKIP_REASON_FIELD_CLAIMED
    assert record["field"] == {"target": "request", "field": "header", "name": "x-mark"}
    assert record["claimed_by"] == "r1"
    assert record["phase"] == "request"


def test_disabling_the_first_rule_lets_the_second_apply() -> None:
    addon = _addon(_set_header("r1", "first"), _set_header("r2", "second"))
    addon.update_rule("r1", {"enabled": False})
    flow = _make_flow()
    _run(addon.request(flow))

    assert flow.request.headers["X-Mark"] == "second"
    assert flow.metadata["mitmproxy_mcp_rules_applied"] == ["r2"]
    assert SKIPPED_KEY not in flow.metadata


def test_disabling_a_whole_ruleset_lets_the_next_one_apply() -> None:
    addon = RulesAddon()
    addon.add_ruleset(RuleSet(id="s1", enabled=True, rules=[_set_header("r1", "first")]))
    addon.add_ruleset(RuleSet(id="s2", enabled=True, rules=[_set_header("r2", "second")]))
    addon.set_ruleset_enabled("s1", False)

    flow = _make_flow()
    _run(addon.request(flow))
    assert flow.request.headers["X-Mark"] == "second"


# ---------------------------------------------------------------------------
# What counts as the same field
# ---------------------------------------------------------------------------


def test_header_name_matching_is_case_insensitive() -> None:
    addon = _addon(_set_header("r1", "first", name="X-Mark"), _set_header("r2", "second", name="x-mark"))
    flow = _make_flow()
    _run(addon.request(flow))
    assert len(flow.request.headers.get_all("X-Mark")) == 1
    assert flow.request.headers["X-Mark"] == "first"


def test_request_and_response_headers_are_different_fields() -> None:
    addon = _addon(
        _set_header("req", "r", name="X-Same", target="request"),
        _set_header("resp", "p", name="X-Same", target="response", phase="response"),
    )
    flow = _make_flow()
    _make_response(flow)
    _run(addon.request(flow))
    _run(addon.response(flow))
    assert flow.request.headers["X-Same"] == "r"
    assert flow.response.headers["X-Same"] == "p"


def test_different_headers_in_one_rule_both_apply() -> None:
    addon = _addon(
        _rule(
            "r1",
            [
                Action(type="set_header", target="request", name="X-A", value="1"),
                Action(type="set_header", target="request", name="X-B", value="2"),
            ],
        )
    )
    flow = _make_flow()
    _run(addon.request(flow))
    assert flow.request.headers["X-A"] == "1"
    assert flow.request.headers["X-B"] == "2"
    assert SKIPPED_KEY not in flow.metadata


def test_set_path_and_set_query_do_not_conflict() -> None:
    addon = _addon(
        _rule("r1", [Action(type="set_path", path="/p")]),
        _rule("r2", [Action(type="set_query", name="q", value="1")]),
    )
    flow = _make_flow("http://example.com/orig")
    _run(addon.request(flow))
    assert flow.request.path == "/p?q=1"
    assert SKIPPED_KEY not in flow.metadata


def test_two_rules_on_different_query_params_both_apply() -> None:
    addon = _addon(
        _rule("r1", [Action(type="set_query", name="a", value="1")]),
        _rule("r2", [Action(type="set_query", name="b", value="2")]),
    )
    flow = _make_flow("http://example.com/x")
    _run(addon.request(flow))
    assert flow.request.query["a"] == "1"
    assert flow.request.query["b"] == "2"
    assert SKIPPED_KEY not in flow.metadata


def test_two_rules_on_the_same_query_param_do_not_stack() -> None:
    addon = _addon(
        _rule("r1", [Action(type="set_query", name="a", value="1")]),
        _rule("r2", [Action(type="set_query", name="a", value="2")]),
    )
    flow = _make_flow("http://example.com/x")
    _run(addon.request(flow))
    assert flow.request.query.get_all("a") == ["1"]
    assert flow.metadata[SKIPPED_KEY][0]["field"]["name"] == "a"


def test_set_url_blocks_a_later_set_path() -> None:
    addon = _addon(
        _rule("r1", [Action(type="set_url", url="http://example.com/from-url")]),
        _rule("r2", [Action(type="set_path", path="/from-path")]),
    )
    flow = _make_flow("http://example.com/orig")
    _run(addon.request(flow))
    assert flow.request.path == "/from-url"
    assert flow.metadata[SKIPPED_KEY][0]["rule_id"] == "r2"


def test_a_later_set_url_is_skipped_when_the_path_is_taken() -> None:
    addon = _addon(
        _rule("r1", [Action(type="set_path", path="/from-path")]),
        _rule("r2", [Action(type="set_url", url="http://example.com/from-url")]),
    )
    flow = _make_flow("http://example.com/orig")
    _run(addon.request(flow))
    assert flow.request.path == "/from-path"
    assert flow.metadata[SKIPPED_KEY][0]["rule_id"] == "r2"


# ---------------------------------------------------------------------------
# Body and status
# ---------------------------------------------------------------------------


def test_set_body_does_not_stack_with_a_later_replace_body() -> None:
    addon = _addon(
        _rule("r1", [Action(type="set_body", target="request", content="ONE")]),
        _rule("r2", [Action(type="replace_body", target="request", pattern="ONE", replacement="TWO")]),
    )
    flow = _make_flow()
    flow.request.content = b"orig"
    _run(addon.request(flow))
    assert flow.request.content == b"ONE"
    assert flow.metadata[SKIPPED_KEY][0]["field"] == {"target": "request", "field": "body"}


def test_two_replace_body_rules_do_not_stack() -> None:
    addon = _addon(
        _rule("r1", [Action(type="replace_body", target="request", pattern="orig", replacement="A")]),
        _rule("r2", [Action(type="replace_body", target="request", pattern="A", replacement="AB")]),
    )
    flow = _make_flow()
    flow.request.content = b"orig"
    _run(addon.request(flow))
    # If the second rule stacked, the body would be "AB".
    assert flow.request.content == b"A"


def test_request_and_response_bodies_are_different_fields() -> None:
    addon = _addon(
        _rule("req", [Action(type="set_body", target="request", content="REQ")]),
        _rule("resp", [Action(type="set_body", target="response", content="RESP")], phase="response"),
    )
    flow = _make_flow()
    _make_response(flow)
    _run(addon.request(flow))
    _run(addon.response(flow))
    assert flow.request.content == b"REQ"
    assert flow.response.content == b"RESP"


def test_only_one_rule_sets_the_status() -> None:
    addon = _addon(
        _rule("r1", [Action(type="set_status", status_code=201)], phase="response"),
        _rule("r2", [Action(type="set_status", status_code=500)], phase="response"),
    )
    flow = _make_flow()
    _make_response(flow)
    _run(addon.response(flow))
    assert flow.response.status_code == 201
    assert flow.metadata[SKIPPED_KEY][0]["field"] == {"target": "response", "field": "status_code"}


# ---------------------------------------------------------------------------
# Partial blocking inside one rule
# ---------------------------------------------------------------------------


def test_only_the_conflicting_action_of_a_rule_is_skipped() -> None:
    addon = _addon(
        _set_header("r1", "first", name="X-A"),
        _rule(
            "r2",
            [
                Action(type="set_header", target="request", name="X-A", value="second"),
                Action(type="set_header", target="request", name="X-B", value="b"),
            ],
        ),
    )
    flow = _make_flow()
    _run(addon.request(flow))
    assert flow.request.headers["X-A"] == "first"
    assert flow.request.headers["X-B"] == "b"
    skipped = flow.metadata[SKIPPED_KEY]
    assert [(s["rule_id"], s["field"]["name"]) for s in skipped] == [("r2", "x-a")]
    # The rule did apply (part of it), so it is in the applied list.
    assert flow.metadata["mitmproxy_mcp_rules_applied"] == ["r1", "r2"]


def test_a_rule_whose_every_write_is_skipped_is_not_listed_as_applied() -> None:
    addon = _addon(
        _set_header("r1", "first"),
        _rule(
            "r2",
            [
                Action(type="set_header", target="request", name="X-Mark", value="second"),
                Action(type="set_header", target="request", name="X-Mark", value="third"),
            ],
        ),
    )
    flow = _make_flow()
    _run(addon.request(flow))
    assert flow.metadata["mitmproxy_mcp_rules_applied"] == ["r1"]
    # Both of r2's writes were refusals, and both are recorded.
    assert len(flow.metadata[SKIPPED_KEY]) == 2


def test_a_fully_skipped_rule_still_holds_the_flow_if_it_intercepts() -> None:
    """intercept is a control action: a claimed field must not disable a breakpoint."""
    addon = _addon(
        _set_header("r1", "first"),
        _rule(
            "bp",
            [
                Action(type="set_header", target="request", name="X-Mark", value="second"),
                Action(type="intercept"),
            ],
        ),
    )
    flow = _make_flow()
    _run(addon.request(flow))
    assert flow.intercepted is True
    assert [p.rule_id for p in addon.list_pending()] == ["bp"]


def test_control_actions_are_never_blocked() -> None:
    addon = _addon(
        _rule("r1", [Action(type="comment", comment="first")]),
        _rule("r2", [Action(type="comment", comment="second")]),
    )
    flow = _make_flow()
    _run(addon.request(flow))
    assert flow.comment == "second"
    assert SKIPPED_KEY not in flow.metadata


# ---------------------------------------------------------------------------
# Skip record surfaces
# ---------------------------------------------------------------------------


def test_skip_event_is_emitted() -> None:
    buffer = EventBuffer()
    addon = RulesAddon(event_buffer=buffer)
    addon.add_rule(_set_header("r1", "first"))
    addon.add_rule(_set_header("r2", "second"))
    flow = _make_flow()
    _run(addon.request(flow))
    skipped_events = [e for e in buffer.latest(limit=10) if e.get("type") == "rule:skipped"]
    assert len(skipped_events) == 1
    assert skipped_events[0]["skipped"][0]["rule_id"] == "r2"


def test_skip_record_carries_the_ruleset_id() -> None:
    addon = RulesAddon()
    addon.add_ruleset(RuleSet(id="s1", rules=[_set_header("r1", "first")]))
    addon.add_ruleset(RuleSet(id="s2", rules=[_set_header("r2", "second")]))
    flow = _make_flow()
    _run(addon.request(flow))
    assert flow.metadata[SKIPPED_KEY][0]["ruleset_id"] == "s2"


def test_flow_model_exposes_applied_and_skipped() -> None:
    from mitmproxy_mcp.models import flow_to_model

    addon = _addon(_set_header("r1", "first"), _set_header("r2", "second"))
    flow = _make_flow()
    _run(addon.request(flow))
    model = flow_to_model(flow, store_id=1)
    assert model.rules_applied == ["r1"]
    assert model.rules_skipped[0]["rule_id"] == "r2"


def test_two_actions_on_one_field_inside_a_rule_keep_their_order() -> None:
    """Conflict rules are between rules: one rule may still clean then set.

    ``remove_header`` followed by ``set_header`` in a single rule is the usual
    way to force a single header value, so the second action must run.
    """
    addon = _addon(
        _rule(
            "r1",
            [
                Action(type="remove_header", target="request", name="X-Multi"),
                Action(type="set_header", target="request", name="X-Multi", value="single"),
            ],
        )
    )
    flow = _make_flow()
    flow.request.headers.set_all("X-Multi", ["a", "b"])
    _run(addon.request(flow))
    assert flow.request.headers.get_all("X-Multi") == ["single"]
    assert SKIPPED_KEY not in flow.metadata


def test_a_failed_action_does_not_claim_its_field() -> None:
    """A rule whose write raised must not block later rules from that field."""
    addon = _addon(
        # set_url with a URL that mitmproxy refuses to parse raises while running.
        _rule("broken", [Action(type="set_url", url="http://example.com:notaport/x")]),
        _set_header("later", "applied", name="X-Mark"),
    )
    flow = _make_flow()
    _run(addon.request(flow))
    assert flow.request.headers["X-Mark"] == "applied"
    assert SKIPPED_KEY not in flow.metadata
