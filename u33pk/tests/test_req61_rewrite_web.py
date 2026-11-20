"""Contract tests for the same-origin /rewrite/* endpoints.

These run against a real ``mitmweb`` tornado ``Application`` (built with the
same settings mitmproxy uses: ``xsrf_cookies=True`` and mitmweb's own auth
handler base), so they exercise authentication and XSRF for real instead of
trusting that a route "should" work.

Nothing here starts a proxy: the handler base is mitmproxy's own
``RequestHandler``, which needs an application whose ``master`` has a
``view``. A ``WebMaster`` is cheap to construct and gives exactly that.
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


class RewriteEndpointTest(AsyncHTTPTestCase):
    """A mitmweb application with only the rewrite routes, real auth enabled."""

    def get_app(self):
        self.manager = _make_manager()
        # WebMaster needs a running event loop during construction (it spawns
        # addon tasks), so build it on the test's own loop.
        async def _build_master() -> WebMaster:
            return WebMaster(options.Options(listen_port=0), with_termlog=False)

        # The io_loop is not running yet, so its asyncio loop can drive this
        # one construction and then be reused for the test itself.
        self.master = self.io_loop.asyncio_loop.run_until_complete(_build_master())
        # Tornado's own application with the mitmweb settings that matter:
        # the auth cookie name and checker come from the real WebAuth addon.
        auth_addon = self.master.addons.get("webauth")
        from tornado import web

        app = web.Application(
            handlers(self.manager),
            xsrf_cookies=True,
            xsrf_cookie_name="_mitmproxy_xsrf",
            xsrf_cookie_kwargs=dict(samesite="Strict"),
            cookie_secret="test-secret",
            is_valid_password=lambda password: password == "secret-token",
            auth_cookie_name=auth_addon.auth_cookie_name,
            compiled_template_cache=False,
        )
        app.master = self.master
        return app

    # -- helpers -------------------------------------------------------
    def _url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.get_http_port()}{path}"

    def _login(self) -> None:
        """Exchange the startup token for the auth cookie the WebUI carries."""
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
            path,
            method="POST",
            body=json.dumps(payload),
            headers=headers,
            **kwargs,
        )

    def _json(self, response) -> dict:
        return json.loads(response.body.decode())


class TestAuth(RewriteEndpointTest):
    def test_get_pending_requires_auth(self) -> None:
        response = self.fetch(f"{PREFIX}/pending")
        assert response.code == 403

    def test_get_rules_requires_auth(self) -> None:
        response = self.fetch(f"{PREFIX}/rules")
        assert response.code == 403

    def test_token_query_string_logs_in(self) -> None:
        self._login()
        response = self.fetch(f"{PREFIX}/pending", headers=self._auth_header())
        assert response.code == 200
        assert self._json(response) == {"pending": []}

    def test_post_with_wrong_xsrf_token_is_refused(self) -> None:
        """A supplied token is verified, not trusted."""
        self._login()
        response = self._post(
            f"{PREFIX}/rules/delete",
            {"id": "r1"},
            headers={"X-XSRFToken": "2|00000000|deadbeef|123"},
        )
        assert response.code == 403

    def test_post_without_xsrf_from_same_origin_is_allowed(self) -> None:
        """The index page sets no _xsrf cookie, so the WebUI posts without one.

        The auth cookie is SameSite=Strict, and no cross-site marker is
        present here -- exactly the WebUI's own request.
        """
        self._login()
        response = self._post(f"{PREFIX}/rules", {"id": "r1", "filter": "~u a.com", "actions": []})
        assert response.code == 200
        assert self._json(response)["success"] is True

    def test_cross_site_post_is_refused_even_with_auth_cookie(self) -> None:
        self._login()
        response = self._post(
            f"{PREFIX}/rules",
            {"id": "r1", "filter": "~u a.com", "actions": []},
            headers={"Sec-Fetch-Site": "cross-site"},
        )
        assert response.code == 403

    def test_cross_origin_header_is_refused(self) -> None:
        self._login()
        response = self._post(
            f"{PREFIX}/rules/delete",
            {"id": "r1"},
            headers={"Origin": "http://evil.example"},
        )
        assert response.code == 403

    def test_post_with_valid_xsrf_token_is_allowed(self) -> None:
        self._login()
        response = self.fetch(f"{PREFIX}/pending", headers=self._auth_header())
        # Reading /pending issues the XSRF cookie; a browser then sends it back
        # and echoes the same value in the header.
        xsrf = self._xsrf_from(response)
        assert xsrf, "GET must hand the browser an XSRF cookie"
        response = self._post(
            f"{PREFIX}/rules/delete",
            {"id": "missing"},
            headers={
                "X-XSRFToken": xsrf,
                "Cookie": f"{self._auth_header()['Cookie']}; _mitmproxy_xsrf={xsrf}",
            },
        )
        # A valid token passes the XSRF gate; the 404 is the real answer.
        assert response.code == 404

    def _xsrf_from(self, response) -> str | None:
        for header in response.headers.get_list("Set-Cookie"):
            if header.startswith("_mitmproxy_xsrf="):
                return header.split("=", 1)[1].split(";", 1)[0]
        return None


class TestPending(RewriteEndpointTest):
    def test_pending_is_empty_on_a_fresh_engine(self) -> None:
        self._login()
        data = self._json(self.fetch(f"{PREFIX}/pending", headers=self._auth_header()))
        assert data == {"pending": []}

    def test_pending_entries_carry_the_contract_fields(self) -> None:
        from mitmproxy_mcp.rules import Action, Rule
        from mitmproxy.test import tflow, tutils

        self._login()
        self.manager.add_rule(
            Rule(id="bp", name="Breakpoint", filter="~u example.com", actions=[Action(type="intercept")])
        )
        flow = tflow.tflow(req=tutils.treq(host="example.com", path="/api/x?y=1"))
        # Hold the flow the way the engine does, without a running proxy.
        self.manager.rules_addon._hold(flow, "bp", "request", rule_name="Breakpoint")

        data = self._json(self.fetch(f"{PREFIX}/pending", headers=self._auth_header()))
        assert len(data["pending"]) == 1
        entry = data["pending"][0]
        for field in (
            "token",
            "flow_id",
            "rule_id",
            "rule_name",
            "phase",
            "host",
            "path",
            "method",
            "created_at",
        ):
            assert field in entry, field
        assert entry["rule_id"] == "bp"
        assert entry["rule_name"] == "Breakpoint"
        assert entry["phase"] == "request"
        assert entry["host"] == "example.com"
        assert entry["path"] == "/api/x?y=1"
        assert entry["method"] == "GET"
        # Epoch *seconds*, an integer: the WebUI multiplies by 1000.
        assert isinstance(entry["created_at"], int)
        assert entry["created_at"] > 1_600_000_000


class TestDecide(RewriteEndpointTest):
    def test_missing_token_is_a_400_in_band_failure(self) -> None:
        self._login()
        response = self._post(f"{PREFIX}/pending/decide", {"decision": "execute"})
        assert response.code == 200
        body = self._json(response)
        assert body["success"] is False
        assert "token" in body["error"]

    def test_unknown_token_answers_success_false(self) -> None:
        """HTTP 200 does not mean it worked; a gone flow must say so."""
        self._login()
        response = self._post(
            f"{PREFIX}/pending/decide", {"token": "nope", "decision": "execute"}
        )
        assert response.code == 200
        body = self._json(response)
        assert body["success"] is False
        assert "nope" in body["error"]

    def test_bad_decision_value_is_refused(self) -> None:
        self._login()
        response = self._post(
            f"{PREFIX}/pending/decide", {"token": "t", "decision": "bogus"}
        )
        assert response.code == 200
        body = self._json(response)
        assert body["success"] is False
        assert "decision" in body["error"]

    def test_decide_execute_releases_the_flow(self) -> None:
        from mitmproxy_mcp.rules import Action, Rule
        from mitmproxy.test import tflow

        self._login()
        self.manager.add_rule(
            Rule(id="bp", filter="~u example.com", actions=[Action(type="intercept")])
        )
        flow = tflow.tflow()
        # No proxy is running in this test, so release the flow through the
        # addon's own fallback instead of the manager's event-loop dispatch.
        self.manager.rules_addon._flow_controller = None
        pending = self.manager.rules_addon._hold(flow, "bp", "request")
        assert flow.intercepted is True

        response = self._post(
            f"{PREFIX}/pending/decide",
            {"token": pending.token, "decision": "execute"},
        )
        body = self._json(response)
        assert body["success"] is True
        assert body["outcome"] == "execute"
        assert flow.intercepted is False
        assert self.manager.list_pending_decisions() == []

        # A second decide on the same token is the "flow already moved on" case.
        again = self._json(
            self._post(
                f"{PREFIX}/pending/decide",
                {"token": pending.token, "decision": "execute"},
            )
        )
        assert again["success"] is False
        assert "pending" in again["error"].lower()


    def test_decide_abort_kills_the_flow(self) -> None:
        from mitmproxy_mcp.rules import Action, Rule
        from mitmproxy.test import tflow

        self._login()
        self.manager.add_rule(
            Rule(id="bp", filter="~u example.com", actions=[Action(type="intercept")])
        )
        self.manager.rules_addon._flow_controller = None
        flow = tflow.tflow()
        pending = self.manager.rules_addon._hold(flow, "bp", "request")

        body = self._json(
            self._post(
                f"{PREFIX}/pending/decide", {"token": pending.token, "decision": "abort"}
            )
        )
        assert body["success"] is True
        assert body["outcome"] == "abort"
        # mitmproxy marks a killed flow with an error, not a boolean.
        assert flow.error is not None and "killed" in str(flow.error).lower()
        assert flow.metadata["mitmproxy_mcp_decision"] == "abort"

    def test_decide_cancel_discards_edits_and_releases(self) -> None:
        """Cancel is not "abort": the flow goes through, the edits do not."""
        from mitmproxy_mcp.rules import Action, Rule
        from mitmproxy.test import tflow

        self._login()
        self.manager.add_rule(
            Rule(
                id="bp",
                filter="~u example.com",
                actions=[
                    Action(type="set_body", target="request", content="EDITED"),
                    Action(type="intercept"),
                ],
            )
        )
        self.manager.rules_addon._flow_controller = None
        flow = tflow.tflow()
        original = flow.request.content
        pending = self.manager.rules_addon._hold(
            flow, "bp", "request", original_request=flow.request.copy()
        )
        assert flow.request.content == original

        body = self._json(
            self._post(
                f"{PREFIX}/pending/decide",
                {"token": pending.token, "decision": "cancel"},
            )
        )
        assert body["success"] is True
        assert body["outcome"] == "cancel"
        assert flow.request.content == original
        assert flow.intercepted is False
        assert flow.error is None


class TestRules(RewriteEndpointTest):
    def test_empty_rules(self) -> None:
        self._login()
        data = self._json(self.fetch(f"{PREFIX}/rules", headers=self._auth_header()))
        assert data["rules"] == []
        assert data["rulesets"] == []

    def test_add_then_list(self) -> None:
        self._login()
        body = {
            "id": "r1",
            "name": "Rewrite",
            "filter": "~u example.com",
            "phase": "request",
            "actions": [{"type": "set_header", "target": "request", "name": "x-a", "value": "1"}],
        }
        response = self._post(f"{PREFIX}/rules", body)
        assert self._json(response)["success"] is True

        data = self._json(self.fetch(f"{PREFIX}/rules", headers=self._auth_header()))
        assert [r["id"] for r in data["rules"]] == ["r1"]
        assert data["rules"][0]["name"] == "Rewrite"

    def test_post_existing_id_updates_in_place(self) -> None:
        self._login()
        self._post(
            f"{PREFIX}/rules",
            {"id": "r1", "name": "one", "filter": "~u example.com", "actions": []},
        )
        self._post(
            f"{PREFIX}/rules",
            {"id": "r1", "name": "two", "filter": "~u other.com", "actions": []},
        )
        data = self._json(self.fetch(f"{PREFIX}/rules", headers=self._auth_header()))
        assert len(data["rules"]) == 1
        assert data["rules"][0]["name"] == "two"
        assert data["rules"][0]["filter"] == "~u other.com"

    def test_post_without_id_is_refused(self) -> None:
        self._login()
        body = self._json(self._post(f"{PREFIX}/rules", {"name": "no id"}))
        assert body["success"] is False
        assert "id" in body["error"]

    def test_invalid_filter_is_refused_with_400(self) -> None:
        self._login()
        response = self._post(
            f"{PREFIX}/rules", {"id": "bad", "filter": "~u (((", "actions": []}
        )
        assert response.code == 400
        body = self._json(response)
        assert body["success"] is False

    def test_malformed_json_is_a_400(self) -> None:
        self._login()
        response = self.fetch(
            f"{PREFIX}/rules",
            method="POST",
            body="{not json",
            headers={"Content-Type": "application/json", **self._auth_header()},
        )
        assert response.code == 400

    def test_enable_and_disable(self) -> None:
        self._login()
        self._post(
            f"{PREFIX}/rules",
            {"id": "r1", "filter": "~u example.com", "actions": []},
        )
        body = self._json(
            self._post(f"{PREFIX}/rules/enable", {"id": "r1", "enabled": False})
        )
        assert body["success"] is True
        assert body["rule"]["enabled"] is False
        data = self._json(self.fetch(f"{PREFIX}/rules", headers=self._auth_header()))
        assert data["rules"][0]["enabled"] is False

    def test_enable_unknown_rule_is_404(self) -> None:
        self._login()
        response = self._post(f"{PREFIX}/rules/enable", {"id": "ghost", "enabled": True})
        assert response.code == 404
        assert self._json(response)["success"] is False

    def test_enable_rejects_non_boolean(self) -> None:
        self._login()
        body = self._json(
            self._post(f"{PREFIX}/rules/enable", {"id": "r1", "enabled": "yes"})
        )
        assert body["success"] is False

    def test_delete(self) -> None:
        self._login()
        self._post(
            f"{PREFIX}/rules",
            {"id": "r1", "filter": "~u example.com", "actions": []},
        )
        assert self._json(self._post(f"{PREFIX}/rules/delete", {"id": "r1"}))["success"] is True
        data = self._json(self.fetch(f"{PREFIX}/rules", headers=self._auth_header()))
        assert data["rules"] == []

    def test_delete_unknown_is_404(self) -> None:
        self._login()
        response = self._post(f"{PREFIX}/rules/delete", {"id": "ghost"})
        assert response.code == 404


class TestRuleSets(RewriteEndpointTest):
    """Rule-set semantics from REQ-6.2 must be visible through the endpoints."""

    def test_ruleset_is_listed_with_its_master_switch(self) -> None:
        from mitmproxy_mcp.rules import Rule, RuleSet

        self._login()
        self.manager.add_ruleset(
            RuleSet(
                id="s1",
                name="Mobile",
                rules=[Rule(id="a", filter="~u example.com", actions=[])],
            )
        )
        data = self._json(self.fetch(f"{PREFIX}/rules", headers=self._auth_header()))
        assert [s["id"] for s in data["rulesets"]] == ["s1"]
        assert data["rulesets"][0]["enabled"] is True
        assert [r["id"] for r in data["rulesets"][0]["rules"]] == ["a"]
        # Listed in evaluation order, and the rule says which set owns it.
        assert [r["id"] for r in data["rules"]] == ["a"]
        assert data["rules"][0]["ruleset_id"] == "s1"

    def test_ruleset_master_switch(self) -> None:
        from mitmproxy_mcp.rules import RuleSet

        self._login()
        self.manager.add_ruleset(RuleSet(id="s1", name="Mobile"))
        body = self._json(
            self._post(f"{PREFIX}/rulesets/enable", {"id": "s1", "enabled": False})
        )
        assert body["success"] is True
        assert body["ruleset"]["enabled"] is False
        data = self._json(self.fetch(f"{PREFIX}/rules", headers=self._auth_header()))
        assert data["rulesets"][0]["enabled"] is False

    def test_ruleset_toggle_unknown_is_404(self) -> None:
        self._login()
        response = self._post(f"{PREFIX}/rulesets/enable", {"id": "ghost", "enabled": True})
        assert response.code == 404

    def test_editing_a_rule_does_not_move_it_between_sets(self) -> None:
        """Membership changes only through the rule-set commands."""
        from mitmproxy_mcp.rules import Rule, RuleSet

        self._login()
        self.manager.add_ruleset(
            RuleSet(id="s1", name="Mobile", rules=[Rule(id="a", filter="~u example.com", actions=[])])
        )
        self._post(
            f"{PREFIX}/rules",
            {
                "id": "a",
                "filter": "~u example.com",
                "name": "renamed",
                "ruleset_id": None,
                "actions": [],
            },
        )
        data = self._json(self.fetch(f"{PREFIX}/rules", headers=self._auth_header()))
        assert data["rules"][0]["ruleset_id"] == "s1"
        assert data["rulesets"][0]["rules"][0]["name"] == "renamed"


class TestEngineParity(RewriteEndpointTest):
    """Rules written over HTTP are the same objects rule_ctl sees.

    REQ-6.2's "first match wins, no stacking" and the rule-set semantics must
    hold for rules created through the endpoints too -- the WebUI must not be
    able to create a rule the engine treats differently.
    """

    def _run_flow(self):
        import asyncio

        from mitmproxy.test import tflow, tutils

        flow = tflow.tflow(req=tutils.treq(host="example.com", path="/api"))
        asyncio.run(self.manager.rules_addon.request(flow))
        return flow

    def test_first_match_wins_for_rules_added_over_http(self) -> None:
        self._login()
        for rule_id, value in (("r1", "first"), ("r2", "second")):
            body = self._json(
                self._post(
                    f"{PREFIX}/rules",
                    {
                        "id": rule_id,
                        "filter": "~u example.com",
                        "phase": "request",
                        "actions": [
                            {
                                "type": "set_header",
                                "target": "request",
                                "name": "x-mark",
                                "value": value,
                            }
                        ],
                    },
                )
            )
            assert body["success"] is True, body

        flow = self._run_flow()
        assert flow.request.headers["x-mark"] == "first"
        skipped = flow.metadata["mitmproxy_mcp_rules_skipped"]
        assert [s["rule_id"] for s in skipped] == ["r2"]
        assert skipped[0]["claimed_by"] == "r1"
        assert skipped[0]["reason"] == "field_already_claimed"

    def test_rule_set_master_switch_governs_evaluation(self) -> None:
        """Turning a set off over HTTP stops its rules from matching."""
        from mitmproxy_mcp.rules import Rule, RuleSet

        self._login()
        self.manager.add_ruleset(
            RuleSet(
                id="s1",
                name="Mobile",
                rules=[
                    Rule(
                        id="a",
                        filter="~u example.com",
                        actions=[
                            {
                                "type": "set_header",
                                "target": "request",
                                "name": "x-set",
                                "value": "on",
                            }
                        ],
                    )
                ],
            )
        )
        self._post(f"{PREFIX}/rulesets/enable", {"id": "s1", "enabled": False})
        flow = self._run_flow()
        assert "x-set" not in flow.request.headers

        self._post(f"{PREFIX}/rulesets/enable", {"id": "s1", "enabled": True})
        flow = self._run_flow()
        assert flow.request.headers["x-set"] == "on"

    def test_disabled_rule_does_not_match(self) -> None:
        self._login()
        self._post(
            f"{PREFIX}/rules",
            {
                "id": "r1",
                "filter": "~u example.com",
                "phase": "request",
                "actions": [
                    {
                        "type": "set_header",
                        "target": "request",
                        "name": "x-off",
                        "value": "1",
                    }
                ],
            },
        )
        self._post(f"{PREFIX}/rules/enable", {"id": "r1", "enabled": False})
        flow = self._run_flow()
        assert "x-off" not in flow.request.headers


@pytest.mark.parametrize(
    "path",
    [
        "/rewrite/pending",
        "/rewrite/pending/decide",
        "/rewrite/rules",
        "/rewrite/rules/enable",
        "/rewrite/rules/delete",
        "/rewrite/rulesets/enable",
    ],
)
def test_route_is_registered(path: str) -> None:
    """The frozen frontend contract lists these exact paths."""
    from mitmproxy_mcp.rewrite_web import PREFIX

    assert path.startswith(PREFIX)
