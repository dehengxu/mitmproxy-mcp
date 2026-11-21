"""REQ-4.2 Focus: focus_hosts / unfocus_host / list_focus.

Focus is a view reorder, not a filter. These tests pin down:

* the on-disk round trip (a real file, re-read on every access);
* append + idempotency, unfocus, empty set;
* case normalisation and the exact-match (no subdomain wildcard) rule;
* that grouping never drops a flow, and that scope/filter state is untouched;
* that all three tools are registered and callable through the MCP layer.
"""

import json

import pytest

from mitmproxy_mcp.core import server
from mitmproxy_mcp.core.focus import (
    DEFAULT_FOCUS_FILE,
    FOCUS_FILE_ENV,
    OTHER_GROUP,
    FocusManager,
    flow_host,
    group_by_focus,
    normalize_host,
)


@pytest.fixture()
def focus_file(tmp_path):
    return tmp_path / "focus.json"


@pytest.fixture()
def manager(focus_file):
    return FocusManager(focus_file)


@pytest.fixture()
def wired(monkeypatch, manager):
    """Point the server's controller at a temp-file FocusManager."""
    monkeypatch.setattr(server.controller, "focus_manager", manager)
    return manager


def _json(text: str):
    return json.loads(text)


# --- storage round trip ---------------------------------------------------


def test_empty_by_default(manager, focus_file):
    assert manager.list_focus() == []
    assert not focus_file.exists()


def test_focus_then_list_reads_back_from_disk(manager, focus_file):
    manager.focus(["api.example.com"])
    # Re-read through a brand new manager: proves it is persisted, not a variable.
    fresh = FocusManager(focus_file)
    assert fresh.list_focus() == ["api.example.com"]


def test_focus_appends_in_order(manager):
    manager.focus(["a.example.com"])
    result = manager.focus(["b.example.com"])
    assert result["added"] == ["b.example.com"]
    assert result["already_focused"] == []
    assert manager.list_focus() == ["a.example.com", "b.example.com"]


def test_focus_is_idempotent(manager):
    manager.focus(["a.example.com", "b.example.com"])
    result = manager.focus(["a.example.com", "b.example.com"])
    assert result["added"] == []
    assert result["already_focused"] == ["a.example.com", "b.example.com"]
    assert manager.list_focus() == ["a.example.com", "b.example.com"]


def test_focus_same_host_twice_in_one_call(manager):
    result = manager.focus(["a.example.com", "A.example.com", " a.example.com "])
    assert result["added"] == ["a.example.com"]
    assert result["already_focused"] == ["a.example.com"]
    assert manager.list_focus() == ["a.example.com"]


def test_unfocus_removes_host(manager):
    manager.focus(["a.example.com", "b.example.com"])
    result = manager.unfocus("b.example.com")
    assert result["removed"] is True
    assert result["focused_hosts"] == ["a.example.com"]
    assert manager.list_focus() == ["a.example.com"]


def test_unfocus_unknown_host_is_noop(manager):
    manager.focus(["a.example.com"])
    result = manager.unfocus("nope.example.com")
    assert result["removed"] is False
    assert manager.list_focus() == ["a.example.com"]


def test_unfocus_last_host_yields_empty_set(manager, focus_file):
    manager.focus(["a.example.com"])
    manager.unfocus("a.example.com")
    assert manager.list_focus() == []
    assert FocusManager(focus_file).list_focus() == []


def test_corrupt_file_reads_as_empty_and_next_write_repairs(manager, focus_file):
    focus_file.write_text("{not json", encoding="utf-8")
    assert manager.list_focus() == []
    manager.focus(["a.example.com"])
    assert json.loads(focus_file.read_text(encoding="utf-8"))["focused_hosts"] == [
        "a.example.com"
    ]


def test_default_path_can_be_overridden_by_env(monkeypatch, tmp_path):
    target = tmp_path / "custom" / "focus.json"
    monkeypatch.setenv(FOCUS_FILE_ENV, str(target))
    mgr = FocusManager()
    mgr.focus(["a.example.com"])
    assert target.exists()
    assert mgr.path == target


def test_default_filename(tmp_path, monkeypatch):
    monkeypatch.delenv(FOCUS_FILE_ENV, raising=False)
    assert FocusManager().path.name == DEFAULT_FOCUS_FILE


# --- host normalisation / matching ---------------------------------------


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("API.Example.com", "api.example.com"),
        ("  api.example.com  ", "api.example.com"),
        ("api.example.com", "api.example.com"),
    ],
)
def test_normalize_host_cases(raw, expected):
    assert normalize_host(raw) == expected


def test_rejects_non_string():
    with pytest.raises(TypeError):
        normalize_host(123)  # type: ignore[arg-type]


def test_empty_host_is_rejected(manager):
    with pytest.raises(ValueError):
        manager.focus([""])
    with pytest.raises(ValueError):
        manager.focus(["   "])
    with pytest.raises(ValueError):
        manager.unfocus("  ")
    assert manager.list_focus() == []


def test_case_normalised_on_write_and_match(manager):
    manager.focus(["API.Example.COM"])
    assert manager.list_focus() == ["api.example.com"]
    assert manager.is_focused("Api.Example.Com") is True
    assert manager.unfocus("API.example.com")["removed"] is True


def test_exact_match_no_subdomain_wildcard(manager):
    manager.focus(["example.com"])
    assert manager.is_focused("example.com") is True
    # No suffix / wildcard matching in either direction.
    assert manager.is_focused("api.example.com") is False
    assert manager.is_focused("notexample.com") is False


def test_no_reverse_wildcard(focus_file):
    """Focusing a subdomain does not focus its parent domain."""
    other = FocusManager(focus_file)
    other.focus(["api.example.com"])
    assert other.is_focused("example.com") is False


def test_port_or_scheme_does_not_match_a_bare_host(manager):
    manager.focus(["example.com"])
    assert manager.is_focused("example.com:8443") is False
    assert manager.is_focused("https://example.com") is False


# --- grouping semantics (reorder, not filter) ----------------------------


def test_group_by_focus_puts_focused_first_and_rest_in_other():
    flows = [
        {"url": "https://other.test/1"},
        {"url": "https://api.example.com/a"},
        {"url": "https://other.test/2"},
        {"url": "https://api.example.com/b"},
    ]
    groups = group_by_focus(flows, ["api.example.com"])
    assert [g["group"] for g in groups] == ["api.example.com", OTHER_GROUP]
    assert [f["url"] for f in groups[0]["flows"]] == [
        "https://api.example.com/a",
        "https://api.example.com/b",
    ]
    assert [f["url"] for f in groups[1]["flows"]] == [
        "https://other.test/1",
        "https://other.test/2",
    ]
    assert groups[0]["focused"] is True
    assert groups[1]["focused"] is False


def test_group_by_focus_never_drops_a_flow():
    flows = [{"url": "https://other.test/1"}, {"url": "https://api.example.com/a"}]
    groups = group_by_focus(flows, ["api.example.com", "idle.example.com"])
    total = sum(len(g["flows"]) for g in groups)
    assert total == len(flows) == 2
    # A focused host with no matching flow contributes no empty group.
    assert [g["group"] for g in groups] == ["api.example.com", OTHER_GROUP]


def test_group_by_focus_without_focus_is_a_single_other_group():
    flows = [{"url": "https://a.test/1"}, {"url": "https://b.test/2"}]
    groups = group_by_focus(flows, [])
    assert [g["group"] for g in groups] == [OTHER_GROUP]
    assert len(groups[0]["flows"]) == 2


def test_group_order_follows_focus_order():
    flows = [{"url": "https://b.test/x"}, {"url": "https://a.test/y"}]
    groups = group_by_focus(flows, ["b.test", "a.test"])
    assert [g["group"] for g in groups] == ["b.test", "a.test"]


def test_group_by_focus_case_insensitive():
    flows = [{"url": "https://API.Example.com/a"}]
    groups = group_by_focus(flows, ["api.example.com"])
    assert groups[0]["group"] == "api.example.com"
    assert len(groups[0]["flows"]) == 1


def test_flow_host_reads_request_host_and_dict_url():
    class _Req:
        host = "API.Example.com"

    class _Flow:
        request = _Req()

    assert flow_host(_Flow()) == "api.example.com"
    assert flow_host({"url": "https://api.example.com:8443/p?q=1"}) == "api.example.com"
    assert flow_host({"host": "Api.Example.COM"}) == "api.example.com"


def test_uncancelled_focus_keeps_original_order():
    """Cancelling restores the ungrouped order -- the flow list itself is never mutated."""
    flows = [
        {"url": "https://other.test/1"},
        {"url": "https://api.example.com/a"},
        {"url": "https://other.test/2"},
    ]
    before = list(flows)
    group_by_focus(flows, ["api.example.com"])
    assert flows == before
    groups = group_by_focus(flows, [])
    assert [f for g in groups for f in g["flows"]] == before


# --- scope / filter independence ----------------------------------------


def test_focus_does_not_touch_scope(monkeypatch, wired):
    monkeypatch.setattr(server.controller.scope_config, "allowed_domains", ["keep.test"])
    before = list(server.controller.scope_config.allowed_domains)
    wired.focus(["api.example.com"])
    assert server.controller.scope_config.allowed_domains == before
    assert server.controller.scope_manager.config.allowed_domains == before


def test_scope_does_not_touch_focus(monkeypatch, wired):
    wired.focus(["api.example.com"])
    server.controller.scope_manager.update_domains(["other.test"])
    try:
        assert wired.list_focus() == ["api.example.com"]
    finally:
        server.controller.scope_manager.update_domains([])


# --- MCP tool layer ------------------------------------------------------


@pytest.mark.asyncio
async def test_tools_round_trip_via_mcp(wired):
    out = _json(await server.focus_hosts(["API.Example.com", "cdn.example.com"]))
    assert out["focused_hosts"] == ["api.example.com", "cdn.example.com"]
    assert out["added"] == ["api.example.com", "cdn.example.com"]
    assert out["other_group"] == OTHER_GROUP

    out = _json(await server.list_focus())
    assert out["focused_hosts"] == ["api.example.com", "cdn.example.com"]

    out = _json(await server.unfocus_host("API.example.com"))
    assert out["removed"] is True
    assert out["focused_hosts"] == ["cdn.example.com"]

    out = _json(await server.list_focus())
    assert out["focused_hosts"] == ["cdn.example.com"]


@pytest.mark.asyncio
async def test_tool_rejects_empty_host_without_raising(wired):
    msg = await server.focus_hosts(["  "])
    assert msg.startswith("Couldn't focus those hosts:")
    assert wired.list_focus() == []


@pytest.mark.asyncio
async def test_tools_reachable_through_mcp_call_tool(wired):
    result = await server.mcp.call_tool("focus_hosts", {"hosts": ["api.example.com"]})
    content = result[0] if isinstance(result, tuple) else result
    payload = _json(content[0].text)
    assert payload["focused_hosts"] == ["api.example.com"]

    result = await server.mcp.call_tool("list_focus", {})
    content = result[0] if isinstance(result, tuple) else result
    assert _json(content[0].text)["focused_hosts"] == ["api.example.com"]

    result = await server.mcp.call_tool("unfocus_host", {"host": "api.example.com"})
    content = result[0] if isinstance(result, tuple) else result
    assert _json(content[0].text)["focused_hosts"] == []


@pytest.mark.asyncio
async def test_focus_tool_schemas():
    tools = {t.name: t for t in await server.mcp.list_tools()}
    assert set(tools) >= {"focus_hosts", "unfocus_host", "list_focus"}
    assert tools["focus_hosts"].inputSchema["required"] == ["hosts"]
    assert tools["unfocus_host"].inputSchema["required"] == ["host"]
    assert tools["list_focus"].inputSchema.get("properties", {}) == {}
    # The docstrings carry the matching rule and the not-a-filter note.
    assert "exact" in tools["focus_hosts"].description.lower()
    assert "not a filter" in tools["focus_hosts"].description.lower()
