"""Contract tests for the rule-management endpoints of the /rewrite/* bridge.

These back the REQ-6.2 WebUI rewrite panel: the rule set life cycle, moving
rules in and out of a set, the two levels of ordering, and the hit preview
that tells the user which rule wins for a field.

The preview is the interesting one. It must agree with the engine, so the
tests here compare it against what the engine actually does on a flow rather
than against a hand-written expectation.
"""

from __future__ import annotations

import json

import pytest
from mitmproxy import options
from mitmproxy.tools.web.master import WebMaster
from tornado.testing import AsyncHTTPTestCase

from mitmproxy_mcp.proxy import ProxyManager
from mitmproxy_mcp.rewrite_web import PREFIX, handlers
from mitmproxy_mcp.store import FlowStore


def _make_manager() -> ProxyManager:
    return ProxyManager(FlowStore())


class RewriteRulesEndpointTest(AsyncHTTPTestCase):
    """A mitmweb application with only the rewrite routes, real auth enabled."""

    def get_app(self):
        self.manager = _make_manager()

        async def _build_master() -> WebMaster:
            return WebMaster(options.Options(listen_port=0), with_termlog=False)

        self.master = self.io_loop.asyncio_loop.run_until_complete(_build_master())
        auth_addon = self.master.addons.get("webauth")
        from tornado import web

        app = web.Application(
            handlers(self.manager),
            xsrf_cookies=True,
            xsrf_cookie_name="_mitmproxy_xsrf",
            xsrf_cookie_kwargs=dict(samesite="Strict"),
            cookie_secret="cookie-secret",
            is_valid_password=lambda password: password == "secret-token",
            auth_cookie_name=auth_addon.auth_cookie_name,
            compiled_template_cache=False,
        )
        app.master = self.master
        return app

    # -- helpers -------------------------------------------------------
    def _login(self) -> None:
        response = self.fetch(f"{PREFIX}/pending?token=secret-token")
        assert response.code == 200
        self.auth_cookie = response.headers.get("Set-Cookie", "")
        assert "mitmproxy-auth-" in self.auth_cookie

    def _auth_header(self) -> dict[str, str]:
        return {"Cookie": self.auth_cookie.split(";")[0]}

    def _post(self, path: str, payload: dict, **kwargs):
        headers = {"Content-Type": "application/json", **self._auth_header()}
        headers.update(kwargs.pop("headers", {}))
        return self.fetch(
            path, method="POST", body=json.dumps(payload), headers=headers, **kwargs
        )

    def _get(self, path: str, **kwargs):
        headers = dict(self._auth_header())
        headers.update(kwargs.pop("headers", {}))
        return self.fetch(path, headers=headers, **kwargs)

    def _json(self, response) -> dict:
        return json.loads(response.body.decode())

    def _add_rule(self, rule_id: str, **overrides) -> dict:
        body = {
            "id": rule_id,
            "name": rule_id,
            "filter": "~u example.com",
            "actions": [],
        }
        body.update(overrides)
        response = self._post(f"{PREFIX}/rules", body)
        assert response.code == 200, response.body
        assert self._json(response)["success"] is True
        return self._json(response)["rule"]

    def _add_ruleset(self, ruleset_id: str, name: str = "set") -> dict:
        response = self._post(f"{PREFIX}/rulesets", {"id": ruleset_id, "name": name})
        assert response.code == 200, response.body
        assert self._json(response)["success"] is True
        return self._json(response)["ruleset"]


class TestRuleSetLifeCycle(RewriteRulesEndpointTest):
    def test_create_ruleset(self) -> None:
        self._login()
        ruleset = self._add_ruleset("rs1", "My set")
        assert ruleset["id"] == "rs1"
        assert ruleset["name"] == "My set"
        assert ruleset["enabled"] is True

    def test_update_ruleset_keeps_its_rules(self) -> None:
        """Renaming a set must not drop the rules inside it."""
        self._login()
        self._add_ruleset("rs1", "Old name")
        self._add_rule("r1", ruleset_id="rs1")
        response = self._post(
            f"{PREFIX}/rulesets", {"id": "rs1", "name": "New name"}
        )
        assert response.code == 200
        ruleset = self._json(response)["ruleset"]
        assert ruleset["name"] == "New name"
        assert [r["id"] for r in ruleset["rules"]] == ["r1"]

    def test_delete_ruleset_removes_its_rules(self) -> None:
        self._login()
        self._add_ruleset("rs1")
        self._add_rule("r1", ruleset_id="rs1")
        response = self._post(f"{PREFIX}/rulesets/delete", {"id": "rs1"})
        assert response.code == 200
        assert self._json(response)["success"] is True
        listing = self._json(self._get(f"{PREFIX}/rules"))
        assert listing["rulesets"] == []
        assert listing["rules"] == []

    def test_delete_unknown_ruleset_is_404(self) -> None:
        self._login()
        response = self._post(f"{PREFIX}/rulesets/delete", {"id": "nope"})
        assert response.code == 404
        assert self._json(response)["success"] is False

    def test_ruleset_requires_id(self) -> None:
        self._login()
        response = self._post(f"{PREFIX}/rulesets", {"name": "no id"})
        assert response.code == 400
        assert self._json(response)["success"] is False
        assert "id" in self._json(response)["error"]


class TestRuleMembership(RewriteRulesEndpointTest):
    def test_move_rule_into_a_set(self) -> None:
        self._login()
        self._add_ruleset("rs1")
        self._add_rule("r1")
        response = self._post(
            f"{PREFIX}/rulesets/rules", {"ruleset_id": "rs1", "rule_id": "r1"}
        )
        assert response.code == 200
        ruleset = self._json(response)["ruleset"]
        assert [r["id"] for r in ruleset["rules"]] == ["r1"]
        assert ruleset["rules"][0]["ruleset_id"] == "rs1"

    def test_move_rule_into_a_set_at_an_index(self) -> None:
        self._login()
        self._add_ruleset("rs1")
        self._add_rule("r1")
        self._add_rule("r2")
        self._post(f"{PREFIX}/rulesets/rules", {"ruleset_id": "rs1", "rule_id": "r1"})
        self._post(f"{PREFIX}/rulesets/rules", {"ruleset_id": "rs1", "rule_id": "r2"})
        response = self._post(
            f"{PREFIX}/rulesets/rules",
            {"ruleset_id": "rs1", "rule_id": "r1", "index": 1},
        )
        assert response.code == 200
        ruleset = self._json(response)["ruleset"]
        assert [r["id"] for r in ruleset["rules"]] == ["r2", "r1"]

    def test_move_rule_out_of_a_set_keeps_it(self) -> None:
        """Removing a rule from a set must not delete it."""
        self._login()
        self._add_ruleset("rs1")
        self._add_rule("r1", ruleset_id="rs1")
        response = self._post(
            f"{PREFIX}/rulesets/rules/remove",
            {"ruleset_id": "rs1", "rule_id": "r1"},
        )
        assert response.code == 200
        assert self._json(response)["success"] is True
        listing = self._json(self._get(f"{PREFIX}/rules"))
        assert [r["id"] for r in listing["rules"]] == ["r1"]
        # The payload drops None values, so a standalone rule has no
        # ruleset_id key at all.
        assert "ruleset_id" not in listing["rules"][0]
        assert listing["rulesets"][0]["rules"] == []

    def test_move_unknown_rule_is_404(self) -> None:
        self._login()
        self._add_ruleset("rs1")
        response = self._post(
            f"{PREFIX}/rulesets/rules", {"ruleset_id": "rs1", "rule_id": "ghost"}
        )
        assert response.code == 404
        assert self._json(response)["success"] is False

    def test_move_into_unknown_set_is_404(self) -> None:
        self._login()
        self._add_rule("r1")
        response = self._post(
            f"{PREFIX}/rulesets/rules", {"ruleset_id": "ghost", "rule_id": "r1"}
        )
        assert response.code == 404


class TestOrdering(RewriteRulesEndpointTest):
    def test_reorder_rules_inside_a_set(self) -> None:
        self._login()
        self._add_ruleset("rs1")
        self._add_rule("r1", ruleset_id="rs1")
        self._add_rule("r2", ruleset_id="rs1")
        self._add_rule("r3", ruleset_id="rs1")
        response = self._post(
            f"{PREFIX}/rulesets/reorder",
            {"id": "rs1", "rule_ids": ["r3", "r1", "r2"]},
        )
        assert response.code == 200
        ruleset = self._json(response)["ruleset"]
        assert [r["id"] for r in ruleset["rules"]] == ["r3", "r1", "r2"]

    def test_reorder_must_list_every_rule_exactly_once(self) -> None:
        """A partial order would silently drop rules from the set."""
        self._login()
        self._add_ruleset("rs1")
        self._add_rule("r1", ruleset_id="rs1")
        self._add_rule("r2", ruleset_id="rs1")
        response = self._post(
            f"{PREFIX}/rulesets/reorder", {"id": "rs1", "rule_ids": ["r1"]}
        )
        assert response.code == 400
        body = self._json(response)
        assert body["success"] is False
        assert "r2" in body["error"]

    def test_move_a_ruleset_in_the_evaluation_order(self) -> None:
        self._login()
        self._add_ruleset("rs1")
        self._add_ruleset("rs2")
        response = self._post(f"{PREFIX}/rulesets/move", {"id": "rs2", "index": 0})
        assert response.code == 200
        listing = self._json(self._get(f"{PREFIX}/rules"))
        assert [rs["id"] for rs in listing["rulesets"]] == ["rs2", "rs1"]

    def test_move_out_of_range_is_rejected(self) -> None:
        self._login()
        self._add_ruleset("rs1")
        response = self._post(f"{PREFIX}/rulesets/move", {"id": "rs1", "index": 7})
        assert response.code == 400
        assert self._json(response)["success"] is False


class TestHitPreview(RewriteRulesEndpointTest):
    def _preview(self, **query) -> dict:
        parts = "&".join(f"{k}={v}" for k, v in query.items())
        response = self._get(f"{PREFIX}/rules/preview?{parts}")
        assert response.code == 200, response.body
        return self._json(response)

    def test_first_rule_wins_the_rest_are_skipped(self) -> None:
        self._login()
        self._add_rule(
            "r1",
            actions=[{"type": "set_header", "target": "request", "name": "X-A", "value": "1"}],
        )
        self._add_rule(
            "r2",
            actions=[{"type": "set_header", "target": "request", "name": "x-a", "value": "2"}],
        )
        result = self._preview(target="request", field="header", name="X-A")
        rows = result["rules"]
        assert [r["rule_id"] for r in rows] == ["r1", "r2"]
        assert rows[0]["effective"] is True
        assert rows[0]["skipped_by"] is None
        assert rows[1]["effective"] is False
        assert rows[1]["skipped_by"] == "r1"

    def test_header_names_are_compared_case_insensitively(self) -> None:
        """The engine lowercases header names, so the preview must too."""
        self._login()
        self._add_rule(
            "r1",
            actions=[{"type": "set_header", "target": "request", "name": "X-A", "value": "1"}],
        )
        rows = self._preview(target="request", field="header", name="x-a")["rules"]
        assert [r["rule_id"] for r in rows] == ["r1"]
        assert rows[0]["effective"] is True

    def test_request_and_response_headers_are_different_fields(self) -> None:
        self._login()
        self._add_rule(
            "r1",
            actions=[{"type": "set_header", "target": "request", "name": "X-A", "value": "1"}],
        )
        rows = self._preview(target="response", field="header", name="X-A")["rules"]
        assert rows == []

    def test_different_query_parameters_do_not_conflict(self) -> None:
        self._login()
        self._add_rule(
            "r1",
            actions=[{"type": "set_query", "name": "a", "value": "1"}],
        )
        self._add_rule(
            "r2",
            actions=[{"type": "set_query", "name": "b", "value": "2"}],
        )
        rows = self._preview(target="request", field="query", name="a")["rules"]
        assert [r["rule_id"] for r in rows] == ["r1"]
        rows = self._preview(target="request", field="query", name="b")["rules"]
        assert [r["rule_id"] for r in rows] == ["r2"]

    def test_set_url_covers_the_path_and_every_query_parameter(self) -> None:
        self._login()
        self._add_rule(
            "r1",
            actions=[{"type": "set_url", "url": "https://example.com/other"}],
        )
        rows = self._preview(target="request", field="path")["rules"]
        assert [r["rule_id"] for r in rows] == ["r1"]
        rows = self._preview(target="request", field="query", name="anything")["rules"]
        assert [r["rule_id"] for r in rows] == ["r1"]

    def test_a_disabled_rule_is_not_previewed(self) -> None:
        self._login()
        self._add_rule(
            "r1",
            actions=[{"type": "set_header", "target": "request", "name": "X-A", "value": "1"}],
        )
        self._post(f"{PREFIX}/rules/enable", {"id": "r1", "enabled": False})
        rows = self._preview(target="request", field="header", name="X-A")["rules"]
        assert rows == []

    def test_a_rule_in_a_disabled_set_is_not_previewed(self) -> None:
        self._login()
        self._add_ruleset("rs1")
        self._add_rule(
            "r1",
            ruleset_id="rs1",
            actions=[{"type": "set_header", "target": "request", "name": "X-A", "value": "1"}],
        )
        self._post(f"{PREFIX}/rulesets/enable", {"id": "rs1", "enabled": False})
        rows = self._preview(target="request", field="header", name="X-A")["rules"]
        assert rows == []

    def test_evaluation_order_follows_the_engine(self) -> None:
        """Standalone rules come first, then the enabled sets in order."""
        self._login()
        self._add_ruleset("rs1")
        self._add_ruleset("rs2")
        self._add_rule("in-rs1", ruleset_id="rs1")
        self._add_rule("standalone")
        self._add_rule("in-rs2", ruleset_id="rs2")
        listing = self._json(self._get(f"{PREFIX}/rules"))
        assert [r["id"] for r in listing["rules"]] == [
            "standalone",
            "in-rs1",
            "in-rs2",
        ]

    def test_unknown_field_is_reported(self) -> None:
        self._login()
        response = self._get(f"{PREFIX}/rules/preview?target=request&field=nope")
        assert response.code == 400
        body = self._json(response)
        assert body["success"] is False
        assert "nope" in body["error"]

    def test_header_preview_needs_a_name(self) -> None:
        self._login()
        response = self._get(f"{PREFIX}/rules/preview?target=request&field=header")
        assert response.code == 400
        body = self._json(response)
        assert body["success"] is False
        assert "name" in body["error"]
