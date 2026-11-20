"""REQ-6.2: rule_ctl rule-set commands and the new read-only tools."""

from __future__ import annotations

import pytest
from mitmproxy_mcp.server import redaction_policy, rule_contract, rule_ctl
from mitmproxy_mcp.tool_info import get_tool_info


@pytest.fixture(autouse=True)
def _clean_rules():
    rule_ctl(cmd="clear")
    yield
    rule_ctl(cmd="clear")


def test_ruleset_list_is_empty_at_start() -> None:
    r = rule_ctl(cmd="ruleset_list")
    assert r["success"] is True
    assert r["rulesets"] == []


def test_ruleset_add_requires_ruleset() -> None:
    r = rule_ctl(cmd="ruleset_add")
    assert r["success"] is False
    assert "ruleset" in r["error"]


def test_ruleset_add_and_list_roundtrip() -> None:
    r = rule_ctl(cmd="ruleset_add", ruleset={"id": "s1", "name": "API rewrite"})
    assert r["success"] is True
    assert r["ruleset"]["id"] == "s1"

    r = rule_ctl(cmd="ruleset_list")
    assert [rs["id"] for rs in r["rulesets"]] == ["s1"]


def test_ruleset_add_rule_and_reorder() -> None:
    rule_ctl(cmd="ruleset_add", ruleset={"id": "s1"})
    for rid in ("a", "b"):
        r = rule_ctl(
            cmd="ruleset_add_rule",
            ruleset_id="s1",
            rule={
                "id": rid,
                "filter": "~u example.com",
                "phase": "request",
                "actions": [{"type": "set_header", "target": "request", "name": "X-" + rid, "value": "1"}],
            },
        )
        assert r["success"] is True

    r = rule_ctl(cmd="ruleset_reorder", ruleset_id="s1", rule_ids=["b", "a"])
    assert r["success"] is True
    assert [x["id"] for x in r["ruleset"]["rules"]] == ["b", "a"]


def test_ruleset_add_rule_places_at_index() -> None:
    rule_ctl(cmd="ruleset_add", ruleset={"id": "s1"})
    for rid in ("a", "c"):
        rule_ctl(
            cmd="ruleset_add_rule",
            ruleset_id="s1",
            rule={"id": rid, "filter": "~u example.com", "actions": [{"type": "kill"}]},
        )
    rule_ctl(
        cmd="ruleset_add_rule",
        ruleset_id="s1",
        index=1,
        rule={"id": "b", "filter": "~u example.com", "actions": [{"type": "kill"}]},
    )
    r = rule_ctl(cmd="ruleset_list")
    assert [x["id"] for x in r["rulesets"][0]["rules"]] == ["a", "b", "c"]


def test_ruleset_enable_disable() -> None:
    rule_ctl(cmd="ruleset_add", ruleset={"id": "s1", "enabled": True})
    r = rule_ctl(cmd="ruleset_disable", ruleset_id="s1")
    assert r["success"] is True
    assert r["ruleset"]["enabled"] is False
    r = rule_ctl(cmd="ruleset_enable", ruleset_id="s1")
    assert r["ruleset"]["enabled"] is True


def test_ruleset_update_name() -> None:
    rule_ctl(cmd="ruleset_add", ruleset={"id": "s1", "name": "old"})
    r = rule_ctl(cmd="ruleset_update", ruleset_id="s1", updates={"name": "new"})
    assert r["success"] is True
    assert r["ruleset"]["name"] == "new"


def test_ruleset_remove_rule() -> None:
    rule_ctl(cmd="ruleset_add", ruleset={"id": "s1"})
    rule_ctl(
        cmd="ruleset_add_rule",
        ruleset_id="s1",
        rule={"id": "a", "filter": "~u example.com", "actions": [{"type": "kill"}]},
    )
    assert rule_ctl(cmd="ruleset_remove_rule", ruleset_id="s1", rule_id="a")["success"] is True
    r = rule_ctl(cmd="ruleset_remove_rule", ruleset_id="s1", rule_id="a")
    assert r["success"] is False
    assert "not found" in r["error"]


def test_ruleset_move() -> None:
    for rid in ("s1", "s2"):
        rule_ctl(cmd="ruleset_add", ruleset={"id": rid})
    r = rule_ctl(cmd="ruleset_move", ruleset_id="s2", index=0)
    assert r["success"] is True
    assert [x["id"] for x in rule_ctl(cmd="ruleset_list")["rulesets"]] == ["s2", "s1"]
    r = rule_ctl(cmd="ruleset_move", ruleset_id="s1", index=9)
    assert r["success"] is False


def test_ruleset_delete() -> None:
    rule_ctl(cmd="ruleset_add", ruleset={"id": "s1"})
    assert rule_ctl(cmd="ruleset_delete", ruleset_id="s1")["success"] is True
    assert rule_ctl(cmd="ruleset_delete", ruleset_id="s1")["success"] is False


def test_ruleset_commands_require_their_ids() -> None:
    for cmd in (
        "ruleset_update",
        "ruleset_delete",
        "ruleset_enable",
        "ruleset_disable",
        "ruleset_add_rule",
        "ruleset_remove_rule",
        "ruleset_reorder",
        "ruleset_move",
    ):
        r = rule_ctl(cmd=cmd)  # type: ignore[arg-type]
        assert r["success"] is False, cmd
        assert "ruleset_id" in r["error"], cmd


def test_list_reports_rules_and_rulesets() -> None:
    rule_ctl(cmd="ruleset_add", ruleset={"id": "s1"})
    rule_ctl(
        cmd="ruleset_add_rule",
        ruleset_id="s1",
        rule={"id": "a", "filter": "~u example.com", "actions": [{"type": "kill"}]},
    )
    r = rule_ctl(cmd="list")
    assert [x["id"] for x in r["rules"]] == ["a"]
    assert r["rules"][0]["ruleset_id"] == "s1"
    assert [x["id"] for x in r["rulesets"]] == ["s1"]


def test_update_rule_can_rename() -> None:
    rule_ctl(
        cmd="add",
        rule={"id": "a", "filter": "~u example.com", "actions": [{"type": "kill"}]},
    )
    r = rule_ctl(cmd="update", rule_id="a", updates={"name": "renamed"})
    assert r["success"] is True
    assert r["rule"]["name"] == "renamed"


# ---------------------------------------------------------------------------
# Read-only tools
# ---------------------------------------------------------------------------


def test_redaction_policy_tool() -> None:
    r = redaction_policy()
    assert r["success"] is True
    assert "Authorization" in r["headers"]
    assert "access_token" in r["names"]


def test_rule_contract_tool_lists_new_action_types() -> None:
    r = rule_contract()
    assert r["success"] is True
    for t in ("set_url", "set_query", "remove_query", "set_path", "set_header"):
        assert t in r["action_types"]
    assert r["skipped_metadata_key"] == "mitmproxy_mcp_rules_skipped"
    assert "rule_id" in r["skipped_record_fields"]


def test_tool_info_documents_the_new_commands() -> None:
    doc = get_tool_info("rule_ctl")["doc"]
    for cmd in (
        "ruleset_list",
        "ruleset_add",
        "ruleset_update",
        "ruleset_delete",
        "ruleset_enable",
        "ruleset_disable",
        "ruleset_add_rule",
        "ruleset_remove_rule",
        "ruleset_reorder",
        "ruleset_move",
    ):
        assert cmd in doc["commands"], cmd


def test_tool_info_covers_the_new_tools() -> None:
    assert get_tool_info("redaction_policy")["success"] is True
    assert get_tool_info("rule_contract")["success"] is True
