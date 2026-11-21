"""``/rewrite/pending`` contract for the auto-clean queue (REQ-6.1).

The WebUI (``ducks/rewrite.ts``) renders a countdown from ``expire_at`` and
drops a row when the API stops listing it. So two things have to hold over
real HTTP: every listed entry carries ``expire_at``/``state``, and deciding a
token that was cleaned up answers ``success: false`` with the reason, at HTTP
200 -- an in-band failure, not a lie.
"""

from __future__ import annotations

import time

from mitmproxy.test import tflow, tutils

from mitmproxy_mcp.rewrite_web import PREFIX
from test_req61_rewrite_web import RewriteEndpointTest


class TestPendingCleanupContract(RewriteEndpointTest):
    def _hold(self, *, live: bool = False):
        from mitmproxy_mcp.rules import Action, Rule

        self.manager.add_rule(
            Rule(
                id="bp",
                name="Breakpoint",
                filter="~u example.com",
                actions=[Action(type="intercept")],
            )
        )
        flow = tflow.tflow(req=tutils.treq(host="example.com", path="/api/x"))
        flow.live = live
        return self.manager.rules_addon._hold(flow, "bp", "request"), flow

    def test_entries_carry_expire_at_and_state(self) -> None:
        self._login()
        decision, _flow = self._hold()
        try:
            data = self._json(
                self.fetch(f"{PREFIX}/pending", headers=self._auth_header())
            )
            assert len(data["pending"]) == 1
            entry = data["pending"][0]
            assert entry["token"] == decision.token
            assert entry["state"] == "pending"
            assert entry["expire_at"] == entry["created_at"] + 300
            assert isinstance(entry["expire_at"], int)
        finally:
            self.manager.rules_addon.stop_reaper()

    def test_expired_token_decides_with_the_expiry_message(self) -> None:
        self._login()
        addon = self.manager.rules_addon
        addon.set_pending_ttl(1)
        decision, _flow = self._hold()
        try:
            time.sleep(1.1)
            # The list swept it out on read: the panel's row disappears.
            data = self._json(
                self.fetch(f"{PREFIX}/pending", headers=self._auth_header())
            )
            assert data["pending"] == []

            response = self._post(
                f"{PREFIX}/pending/decide",
                {"token": decision.token, "decision": "execute"},
            )
            assert response.code == 200
            body = self._json(response)
            assert body["success"] is False
            assert body["error"] == "待决策已过期（TTL 5 分钟），已自动清理"
        finally:
            addon.set_pending_ttl(300)
            addon.stop_reaper()

    def test_disconnected_token_decides_with_the_disconnect_message(self) -> None:
        self._login()
        decision, flow = self._hold()
        try:
            self.manager.rules_addon.client_disconnected(flow.client_conn)

            data = self._json(
                self.fetch(f"{PREFIX}/pending", headers=self._auth_header())
            )
            assert data["pending"] == []

            response = self._post(
                f"{PREFIX}/pending/decide",
                {"token": decision.token, "decision": "abort"},
            )
            assert response.code == 200
            body = self._json(response)
            assert body["success"] is False
            assert body["error"] == "客户端已断开，待决策已取消"
        finally:
            self.manager.rules_addon.stop_reaper()

    def test_unknown_token_keeps_the_original_wording(self) -> None:
        """A token that was never queued still says "No pending decision"."""
        self._login()
        response = self._post(
            f"{PREFIX}/pending/decide",
            {"token": "never-seen", "decision": "execute"},
        )
        assert response.code == 200
        body = self._json(response)
        assert body["success"] is False
        assert "No pending decision for token never-seen" in body["error"]
