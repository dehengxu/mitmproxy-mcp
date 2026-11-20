"""REQ-6.2: rule sets, enabling a whole set, and evaluation order."""

from __future__ import annotations

import asyncio

import pytest
from mitmproxy import http
from mitmproxy.connection import Client, Server

from mitmproxy_mcp.rules import Action, Rule, RuleSet, RulesAddon


def _make_flow(url: str = "http://example.com/") -> http.HTTPFlow:
    req = http.Request.make("GET", url)
    client = Client(peername=("127.0.0.1", 12345), sockname=("127.0.0.1", 8080))
    server = Server(address=(req.host, req.port))
    flow = http.HTTPFlow(client, server)
    flow.request = req
    return flow


def _run(coro):
    return asyncio.run(coro)


def _rule(rule_id: str, **kwargs) -> Rule:
    kwargs.setdefault("filter", "~u example.com")
    kwargs.setdefault("phase", "request")
    return Rule(id=rule_id, **kwargs)


def _set_header(rule_id: str, value: str, target: str = "request", name: str = "X-Mark") -> Rule:
    return _rule(
        rule_id,
        actions=[Action(type="set_header", target=target, name=name, value=value)],
    )


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------


def test_ruleset_marks_its_rules_as_members() -> None:
    rs = RuleSet(id="s1", name="one", rules=[_set_header("r1", "a")])
    assert rs.rules[0].ruleset_id == "s1"


def test_ruleset_rejects_duplicate_rule_ids() -> None:
    with pytest.raises(ValueError):
        RuleSet(id="s1", rules=[_set_header("r1", "a"), _set_header("r1", "b")])


def test_standalone_rule_has_no_ruleset_id() -> None:
    assert _set_header("r1", "a").ruleset_id is None


# ---------------------------------------------------------------------------
# Management
# ---------------------------------------------------------------------------


def test_add_and_list_rulesets() -> None:
    addon = RulesAddon()
    addon.add_ruleset(RuleSet(id="s1", name="first"))
    addon.add_ruleset(RuleSet(id="s2", name="second"))
    assert [rs.id for rs in addon.list_rulesets()] == ["s1", "s2"]


def test_add_ruleset_replaces_in_place_keeping_order() -> None:
    addon = RulesAddon()
    addon.add_ruleset(RuleSet(id="s1", name="first"))
    addon.add_ruleset(RuleSet(id="s2", name="second"))
    addon.add_ruleset(RuleSet(id="s1", name="first-renamed"))
    assert [rs.id for rs in addon.list_rulesets()] == ["s1", "s2"]
    assert addon.list_rulesets()[0].name == "first-renamed"


def test_update_ruleset_name_and_enabled() -> None:
    addon = RulesAddon()
    addon.add_ruleset(RuleSet(id="s1", name="old"))
    updated = addon.update_ruleset("s1", {"name": "new", "enabled": False})
    assert updated is not None
    assert updated.name == "new"
    assert updated.enabled is False


def test_update_unknown_ruleset_returns_none() -> None:
    assert RulesAddon().update_ruleset("nope", {"name": "x"}) is None


def test_update_ruleset_does_not_drop_its_rules() -> None:
    addon = RulesAddon()
    addon.add_ruleset(RuleSet(id="s1", rules=[_set_header("r1", "a")]))
    addon.update_ruleset("s1", {"name": "renamed"})
    assert [r.id for r in addon.list_rulesets()[0].rules] == ["r1"]


def test_add_rule_to_ruleset_sets_membership() -> None:
    addon = RulesAddon()
    addon.add_ruleset(RuleSet(id="s1"))
    addon.add_rule_to_ruleset("s1", _set_header("r1", "a"))
    assert addon.list_rulesets()[0].rules[0].ruleset_id == "s1"
    assert [r.id for r in addon.list_rules()] == ["r1"]


def test_add_rule_to_ruleset_at_index() -> None:
    addon = RulesAddon()
    addon.add_ruleset(RuleSet(id="s1", rules=[_set_header("a", "1"), _set_header("c", "3")]))
    addon.add_rule_to_ruleset("s1", _set_header("b", "2"), index=1)
    assert [r.id for r in addon.list_rulesets()[0].rules] == ["a", "b", "c"]


def test_add_rule_to_ruleset_index_out_of_range() -> None:
    addon = RulesAddon()
    addon.add_ruleset(RuleSet(id="s1"))
    with pytest.raises(ValueError):
        addon.add_rule_to_ruleset("s1", _set_header("r1", "a"), index=5)


def test_add_rule_to_unknown_ruleset_returns_none() -> None:
    assert RulesAddon().add_rule_to_ruleset("nope", _set_header("r1", "a")) is None


def test_adding_a_rule_twice_moves_it_not_duplicates_it() -> None:
    addon = RulesAddon()
    addon.add_rule(_set_header("r1", "a"))
    addon.add_ruleset(RuleSet(id="s1"))
    addon.add_rule_to_ruleset("s1", _set_header("r1", "b"))
    assert [r.id for r in addon.list_rules()] == ["r1"]
    # The rule now lives only inside the set.
    assert addon.list_rules()[0].ruleset_id == "s1"


def test_add_rule_with_unknown_ruleset_id_is_refused() -> None:
    addon = RulesAddon()
    with pytest.raises(ValueError):
        addon.add_rule(_rule("r1", ruleset_id="missing"))


def test_remove_rule_from_ruleset_deletes_it() -> None:
    addon = RulesAddon()
    addon.add_ruleset(RuleSet(id="s1", rules=[_set_header("r1", "a")]))
    assert addon.remove_rule_from_ruleset("s1", "r1") is True
    assert addon.list_rules() == []
    assert addon.remove_rule_from_ruleset("s1", "r1") is False


def test_delete_ruleset_removes_its_rules() -> None:
    addon = RulesAddon()
    addon.add_ruleset(RuleSet(id="s1", rules=[_set_header("r1", "a")]))
    assert addon.delete_ruleset("s1") is True
    assert addon.list_rulesets() == []
    assert addon.list_rules() == []
    assert addon.delete_ruleset("s1") is False


def test_reorder_ruleset_rules() -> None:
    addon = RulesAddon()
    addon.add_ruleset(RuleSet(id="s1", rules=[_set_header("a", "1"), _set_header("b", "2")]))
    addon.reorder_ruleset_rules("s1", ["b", "a"])
    assert [r.id for r in addon.list_rulesets()[0].rules] == ["b", "a"]


def test_reorder_requires_every_rule_exactly_once() -> None:
    addon = RulesAddon()
    addon.add_ruleset(RuleSet(id="s1", rules=[_set_header("a", "1"), _set_header("b", "2")]))
    with pytest.raises(ValueError):
        addon.reorder_ruleset_rules("s1", ["a"])
    with pytest.raises(ValueError):
        addon.reorder_ruleset_rules("s1", ["a", "b", "c"])


def test_move_ruleset_changes_evaluation_order() -> None:
    addon = RulesAddon()
    addon.add_ruleset(RuleSet(id="s1"))
    addon.add_ruleset(RuleSet(id="s2"))
    addon.move_ruleset("s2", 0)
    assert [rs.id for rs in addon.list_rulesets()] == ["s2", "s1"]
    with pytest.raises(ValueError):
        addon.move_ruleset("s2", 5)


def test_delete_rule_reaches_into_rulesets() -> None:
    addon = RulesAddon()
    addon.add_ruleset(RuleSet(id="s1", rules=[_set_header("r1", "a")]))
    assert addon.delete_rule("r1") is True
    assert addon.list_rulesets()[0].rules == []


def test_clear_rules_also_drops_rule_sets() -> None:
    addon = RulesAddon()
    addon.add_ruleset(RuleSet(id="s1", rules=[_set_header("r1", "a")]))
    addon.add_rule(_set_header("r2", "b"))
    assert addon.clear_rules() == 2
    assert addon.list_rulesets() == []
    assert addon.list_rules() == []


def test_update_rule_inside_a_ruleset() -> None:
    addon = RulesAddon()
    addon.add_ruleset(RuleSet(id="s1", rules=[_set_header("r1", "a")]))
    updated = addon.update_rule("r1", {"name": "renamed"})
    assert updated is not None
    assert updated.name == "renamed"
    # Membership survives an update even if updates tried to change it.
    assert addon.list_rulesets()[0].rules[0].ruleset_id == "s1"


# ---------------------------------------------------------------------------
# Evaluation order and set-level enabling
# ---------------------------------------------------------------------------


def test_rules_inside_a_set_are_applied() -> None:
    addon = RulesAddon()
    addon.add_ruleset(RuleSet(id="s1", rules=[_set_header("r1", "set")]))
    flow = _make_flow()
    _run(addon.request(flow))
    assert flow.request.headers["X-Mark"] == "set"
    assert "r1" in flow.metadata["mitmproxy_mcp_rules_applied"]


def test_disabled_ruleset_blocks_all_its_rules() -> None:
    addon = RulesAddon()
    addon.add_ruleset(
        RuleSet(id="s1", enabled=False, rules=[_set_header("r1", "set")])
    )
    flow = _make_flow()
    _run(addon.request(flow))
    assert "X-Mark" not in flow.request.headers


def test_enabling_a_ruleset_reactivates_its_rules() -> None:
    addon = RulesAddon()
    addon.add_ruleset(
        RuleSet(id="s1", enabled=False, rules=[_set_header("r1", "set")])
    )
    addon.set_ruleset_enabled("s1", True)

    flow = _make_flow()
    _run(addon.request(flow))
    assert flow.request.headers["X-Mark"] == "set"


def test_standalone_rules_run_before_rulesets() -> None:
    addon = RulesAddon()
    addon.add_rule(_set_header("standalone", "first"))
    addon.add_ruleset(RuleSet(id="s1", rules=[_set_header("in-set", "second")]))
    flow = _make_flow()
    _run(addon.request(flow))
    # First match wins: the standalone rule owns X-Mark.
    assert flow.request.headers["X-Mark"] == "first"
    assert flow.metadata["mitmproxy_mcp_rules_applied"] == ["standalone"]


def test_rulesets_evaluate_in_their_order() -> None:
    addon = RulesAddon()
    addon.add_ruleset(RuleSet(id="s1", rules=[_set_header("r1", "one")]))
    addon.add_ruleset(RuleSet(id="s2", rules=[_set_header("r2", "two")]))
    flow = _make_flow()
    _run(addon.request(flow))
    assert flow.request.headers["X-Mark"] == "one"

    addon.move_ruleset("s2", 0)
    flow2 = _make_flow()
    _run(addon.request(flow2))
    assert flow2.request.headers["X-Mark"] == "two"


def test_rules_inside_a_set_evaluate_in_list_order() -> None:
    addon = RulesAddon()
    addon.add_ruleset(
        RuleSet(id="s1", rules=[_set_header("a", "first"), _set_header("b", "second")])
    )
    flow = _make_flow()
    _run(addon.request(flow))
    assert flow.request.headers["X-Mark"] == "first"

    addon.reorder_ruleset_rules("s1", ["b", "a"])
    flow2 = _make_flow()
    _run(addon.request(flow2))
    assert flow2.request.headers["X-Mark"] == "second"


def test_rule_level_disable_still_works_inside_an_enabled_set() -> None:
    addon = RulesAddon()
    addon.add_ruleset(
        RuleSet(
            id="s1",
            rules=[_set_header("a", "one", name="X-A"), _set_header("b", "two", name="X-B")],
        )
    )
    addon.update_rule("a", {"enabled": False})
    flow = _make_flow()
    _run(addon.request(flow))
    assert "X-A" not in flow.request.headers
    assert flow.request.headers["X-B"] == "two"
