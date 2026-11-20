"""Server-level contract tests for REQ-6.1 rule_ctl commands."""

from mitmproxy_mcp.server import rule_ctl


def test_pending_without_running_proxy() -> None:
    r = rule_ctl(cmd="pending")
    assert r["success"] is True
    assert r["pending"] == []


def test_update_requires_rule_id() -> None:
    r = rule_ctl(cmd="update", updates={"name": "x"})
    assert r["success"] is False
    assert "rule_id" in r["error"]


def test_update_requires_updates() -> None:
    r = rule_ctl(cmd="update", rule_id="bp")
    assert r["success"] is False
    assert "updates" in r["error"]


def test_decide_requires_token() -> None:
    r = rule_ctl(cmd="decide", decision="execute")
    assert r["success"] is False
    assert "token" in r["error"]


def test_decide_requires_decision() -> None:
    r = rule_ctl(cmd="decide", token="abc")
    assert r["success"] is False
    assert "decision" in r["error"]


def test_decide_unknown_token_reports_error() -> None:
    r = rule_ctl(cmd="decide", token="does-not-exist", decision="execute")
    assert r["success"] is False
    assert "does-not-exist" in r["error"]
