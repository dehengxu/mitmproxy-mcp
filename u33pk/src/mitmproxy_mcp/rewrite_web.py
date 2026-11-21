"""Same-origin HTTP endpoints that expose the rewrite engine to the WebUI.

The mitmweb WebUI that ``ProxyManager`` starts when ``webui=True`` is a
``WebMaster``: its tornado ``Application`` and this package's ``RulesAddon``
live in the same process and on the same origin. The WebUI therefore talks to
the rule engine over plain relative HTTP paths -- no second process, no CORS,
no extra web framework.

Everything here is mounted on the master's *own* ``Application`` (see
``install``). With ``webui=False`` the proxy runs a ``DumpMaster``, which has no
application at all; there the MCP tools (``rule_ctl``) stay the only entry
point and nothing in this module is reachable.

The paths are the frozen contract of the frontend (``ducks/rewrite.ts``)::

    GET  /rewrite/pending          -> {"pending": [...]}
    POST /rewrite/pending/decide   <- {"token", "decision"}

Each pending entry carries ``token``, ``flow_id``, ``rule_id``, ``rule_name``,
``phase``, ``host``, ``path``, ``method``, ``created_at``, ``expire_at``
(``created_at + 300``, epoch seconds) and ``state`` (``"pending"``). A hold
that expires or whose client disconnects is removed from the queue and stops
being listed; deciding its token answers ``success: false`` with the reason.
    GET  /rewrite/rules            -> {"rules": [...], "rulesets": [...]}
    POST /rewrite/rules            <- full rule body (add or update)
    POST /rewrite/rules/enable     <- {"id", "enabled"}
    POST /rewrite/rules/delete     <- {"id"}

``POST /rewrite/rulesets/enable`` (``{"id", "enabled"}``) backs the rule
set master switch. It is an addition to the frozen six because the WebUI shows
set-level toggles; nothing else about the contract changes.

Two rules of the house apply to every handler:

* A rule write goes through ``RulesAddon`` / ``ProxyManager``, the same objects
  ``rule_ctl`` uses. There is one truth about rules; this module never
  re-implements matching, ordering or conflict handling.
* An HTTP 200 does not mean "it worked": deciding a flow can still fail (the
  flow is gone, the token was already used). That answers
  ``{"success": false, "error": "..."}`` so the WebUI keeps the row and shows
  why, instead of dropping it.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from mitmproxy.tools.web.app import RequestHandler as WebRequestHandler
from tornado import web

from mitmproxy_mcp.rules import (
    Rule,
    RuleSet,
    action_claims,
    claims_conflict,
)

if TYPE_CHECKING:  # pragma: no cover
    from mitmproxy.tools.web.master import WebMaster

    from mitmproxy_mcp.proxy import ProxyManager

logger = logging.getLogger(__name__)

#: Path prefix every route below shares; also the WebUI's own prefix.
PREFIX = "/rewrite"


class RewriteRequestHandler(WebRequestHandler):
    """Base for the rewrite routes: mitmweb auth, JSON in, JSON out.

    ``WebRequestHandler`` is mitmproxy's own base class, so subclassing it
    gives these routes the *same* authentication as ``/flows``: the startup
    token, the signed auth cookie, or ``?token=``. A route that skipped that
    would let anything on the loopback interface drive the proxy.
    """

    def initialize(self, manager: ProxyManager) -> None:
        self.manager = manager

    # -- XSRF ----------------------------------------------------------
    def check_xsrf_cookie(self) -> None:
        """Accept a real XSRF token, else require a same-origin POST.

        Tornado turns ``xsrf_cookies=True`` on for the whole mitmweb
        application, and it rejects any POST that carries no token. The WebUI
        does send ``X-XSRFToken`` from the ``_mitmproxy_xsrf`` cookie when the
        cookie exists -- but the index page it is served from never renders
        ``xsrf_form_html()``, so after a token-URL login that cookie is never
        set and every frontend POST would be refused with a bare 403.

        So: if a token is present, verify it exactly as tornado would (a wrong
        token is still a 403). If none is present, fall back to what actually
        protects this surface -- the auth cookie is ``SameSite=Strict`` and a
        cross-site POST announces itself in ``Origin`` / ``Sec-Fetch-Site``.
        A cross-origin request is refused even when it carries the auth cookie.
        """
        # Header first, then the query string: never parse the JSON body as a
        # form, which is what ``get_argument`` would try to do here.
        supplied = (
            self.request.headers.get("X-Xsrftoken")
            or self.request.headers.get("X-Csrftoken")
            or self.get_query_argument("_xsrf", None)
        )
        if supplied:
            return super().check_xsrf_cookie()

        site = self.request.headers.get("Sec-Fetch-Site")
        if site is not None and site not in ("same-origin", "none"):
            raise web.HTTPError(403, "cross-site POST refused")
        origin = self.request.headers.get("Origin")
        if origin and urlparse(origin).netloc != self.request.host:
            raise web.HTTPError(403, "cross-origin POST refused")

    def issue_xsrf_cookie(self) -> None:
        """Make sure the browser has an ``_mitmproxy_xsrf`` cookie to send back.

        The WebUI reads that cookie once and echoes it as ``X-XSRFToken`` on
        every POST. mitmweb's index page is static and never renders
        ``xsrf_form_html()``, so the cookie is otherwise never set -- reading
        the token here is what puts it in the browser.
        """
        self.xsrf_token  # noqa: B018 - property access sets the cookie

    # -- helpers -------------------------------------------------------
    def json_body(self) -> dict[str, Any]:
        """Parse the request body as a JSON object, or raise a 400."""
        raw = self.request.body
        if not raw:
            return {}
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise web.HTTPError(400, f"Malformed JSON: {e}") from e
        if not isinstance(data, dict):
            raise web.HTTPError(400, "Expected a JSON object")
        return data

    def fail(self, error: str, status: int = 200) -> None:
        """Answer ``success: false``; 200 by default, for in-band failures."""
        self.set_status(status)
        self.write({"success": False, "error": error})


def _pending_payload(manager: ProxyManager) -> list[dict[str, Any]]:
    entries = []
    for pending in manager.list_pending_decisions():
        data = pending.model_dump()
        data["created_at"] = int(data["created_at"])
        # Epoch seconds, integer, same unit as created_at: the panel renders it
        # as a countdown. ``state`` is always "pending" here -- an entry that
        # expired or lost its client was already swept out of the queue by
        # ``list_pending_decisions`` and never appears in this list.
        data["expire_at"] = int(data.get("expire_at") or 0)
        entries.append(data)
    return entries


def _rules_payload(manager: ProxyManager) -> dict[str, Any]:
    return {
        # Evaluation order as the engine sees it: standalone rules first, then
        # each rule set's rules. ``ruleset_id`` on a rule says where it lives.
        "rules": [r.model_dump(exclude_none=True) for r in manager.list_rules()],
        "rulesets": [
            rs.model_dump(exclude_none=True) for rs in manager.list_rulesets()
        ],
    }


class PendingHandler(RewriteRequestHandler):
    """``GET /rewrite/pending`` -- the flows currently held for a decision."""

    def get(self) -> None:
        self.issue_xsrf_cookie()
        self.write({"pending": _pending_payload(self.manager)})


class DecideHandler(RewriteRequestHandler):
    """``POST /rewrite/pending/decide`` -- execute / abort / cancel one flow."""

    def post(self) -> None:
        body = self.json_body()
        token = body.get("token")
        decision = body.get("decision")
        if not token:
            return self.fail("token is required")
        if decision not in ("execute", "abort", "cancel"):
            return self.fail(
                "decision must be one of execute, abort, cancel"
            )
        try:
            pending, _ = self.manager.decide_pending(token, decision)
        except KeyError as e:
            # The flow moved on (already decided, or the client gave up). The
            # row is still in the WebUI's list: say so instead of pretending.
            # A cleaned-up entry carries its own reason ("expired", "client
            # disconnected"); a plain KeyError keeps the old wording, quotes
            # stripped.
            message = getattr(e, "message", None) or (
                str(e.args[0]) if e.args else "unknown token"
            )
            return self.fail(message)
        except Exception as e:  # noqa: BLE001 - reported, never swallowed
            logger.warning("rewrite decide failed for token %s: %s", token, e)
            return self.fail(str(e))
        self.write(
            {
                "success": True,
                "decision": pending.model_dump(),
                "outcome": decision,
            }
        )


class RulesHandler(RewriteRequestHandler):
    """``GET``/``POST /rewrite/rules`` -- list, add or update rules."""

    def get(self) -> None:
        self.issue_xsrf_cookie()
        self.write(_rules_payload(self.manager))

    def post(self) -> None:
        body = self.json_body()
        rule_id = body.get("id")
        if not rule_id:
            return self.fail("id is required")
        existing = {r.id for r in self.manager.list_rules()}
        try:
            if rule_id in existing:
                # Editing an existing rule must not move it between rule sets:
                # membership changes only through the rule-set commands.
                data = dict(body)
                data.pop("ruleset_id", None)
                updated = self.manager.update_rule(rule_id, data)
                if updated is None:
                    return self.fail(f"Rule with id {rule_id} not found", 404)
                return self.write(
                    {"success": True, "rule": updated.model_dump(exclude_none=True)}
                )
            rule = Rule(**body)
        except ValueError as e:
            return self.fail(str(e), 400)
        self.manager.add_rule(rule)
        self.write({"success": True, "rule": rule.model_dump(exclude_none=True)})


class RuleEnableHandler(RewriteRequestHandler):
    """``POST /rewrite/rules/enable`` -- turn one rule on or off."""

    def post(self) -> None:
        body = self.json_body()
        rule_id = body.get("id")
        enabled = body.get("enabled")
        if not rule_id:
            return self.fail("id is required")
        if not isinstance(enabled, bool):
            return self.fail("enabled must be true or false")
        updated = self.manager.update_rule(rule_id, {"enabled": enabled})
        if updated is None:
            return self.fail(f"Rule with id {rule_id} not found", 404)
        self.write({"success": True, "rule": updated.model_dump(exclude_none=True)})


class RuleDeleteHandler(RewriteRequestHandler):
    """``POST /rewrite/rules/delete`` -- delete one rule."""

    def post(self) -> None:
        body = self.json_body()
        rule_id = body.get("id")
        if not rule_id:
            return self.fail("id is required")
        if not self.manager.delete_rule(rule_id):
            return self.fail(f"Rule with id {rule_id} not found", 404)
        self.write({"success": True})


class RuleSetEnableHandler(RewriteRequestHandler):
    """``POST /rewrite/rulesets/enable`` -- the set-level master switch."""

    def post(self) -> None:
        body = self.json_body()
        ruleset_id = body.get("id")
        enabled = body.get("enabled")
        if not ruleset_id:
            return self.fail("id is required")
        if not isinstance(enabled, bool):
            return self.fail("enabled must be true or false")
        updated = self.manager.set_ruleset_enabled(ruleset_id, enabled)
        if updated is None:
            return self.fail(f"Rule set with id {ruleset_id} not found", 404)
        self.write(
            {"success": True, "ruleset": updated.model_dump(exclude_none=True)}
        )


class RuleSetHandler(RewriteRequestHandler):
    """``POST /rewrite/rulesets`` -- create or update a rule set."""

    def post(self) -> None:
        body = self.json_body()
        ruleset_id = body.get("id")
        if not ruleset_id:
            return self.fail("id is required", 400)
        name = body.get("name", "")
        enabled = body.get("enabled", True)
        if not isinstance(enabled, bool):
            return self.fail("enabled must be true or false", 400)
        try:
            if any(rs.id == ruleset_id for rs in self.manager.list_rulesets()):
                # Editing a set must not drop the rules inside it: the set
                # update path keeps them and only touches name / enabled.
                updated = self.manager.update_ruleset(
                    ruleset_id, {"name": name, "enabled": enabled}
                )
                if updated is None:
                    return self.fail(f"Rule set with id {ruleset_id} not found", 404)
                return self.write(
                    {"success": True, "ruleset": updated.model_dump(exclude_none=True)}
                )
            ruleset = RuleSet(id=ruleset_id, name=name, enabled=enabled)
        except ValueError as e:
            return self.fail(str(e), 400)
        created = self.manager.add_ruleset(ruleset)
        self.write({"success": True, "ruleset": created.model_dump(exclude_none=True)})


class RuleSetDeleteHandler(RewriteRequestHandler):
    """``POST /rewrite/rulesets/delete`` -- delete a rule set."""

    def post(self) -> None:
        body = self.json_body()
        ruleset_id = body.get("id")
        if not ruleset_id:
            return self.fail("id is required", 400)
        if not self.manager.delete_ruleset(ruleset_id):
            return self.fail(f"Rule set with id {ruleset_id} not found", 404)
        self.write({"success": True})


class RuleSetAddRuleHandler(RewriteRequestHandler):
    """``POST /rewrite/rulesets/rules`` -- move a rule into a rule set."""

    def post(self) -> None:
        body = self.json_body()
        ruleset_id = body.get("ruleset_id")
        rule_id = body.get("rule_id")
        if not ruleset_id:
            return self.fail("ruleset_id is required", 400)
        if not rule_id:
            return self.fail("rule_id is required", 400)
        index = body.get("index")
        if index is not None and not isinstance(index, int):
            return self.fail("index must be an integer", 400)

        # The rule has to be fetched first: moving it means taking the very
        # same rule object out of wherever it is now.
        rule = next((r for r in self.manager.list_rules() if r.id == rule_id), None)
        if rule is None:
            return self.fail(f"Rule with id {rule_id} not found", 404)
        try:
            updated = self.manager.add_rule_to_ruleset(ruleset_id, rule, index)
        except ValueError as e:
            return self.fail(str(e), 400)
        if updated is None:
            return self.fail(f"Rule set with id {ruleset_id} not found", 404)
        self.write({"success": True, "ruleset": updated.model_dump(exclude_none=True)})


class RuleSetRemoveRuleHandler(RewriteRequestHandler):
    """``POST /rewrite/rulesets/rules/remove`` -- move a rule out of a set.

    The rule is not deleted: it becomes a standalone rule again, which keeps
    it in the evaluation order instead of dropping it silently.
    """

    def post(self) -> None:
        body = self.json_body()
        ruleset_id = body.get("ruleset_id")
        rule_id = body.get("rule_id")
        if not ruleset_id:
            return self.fail("ruleset_id is required", 400)
        if not rule_id:
            return self.fail("rule_id is required", 400)
        rule = next(
            (
                r
                for rs in self.manager.list_rulesets()
                if rs.id == ruleset_id
                for r in rs.rules
                if r.id == rule_id
            ),
            None,
        )
        if rule is None:
            return self.fail(
                f"Rule {rule_id} not found in rule set {ruleset_id}", 404
            )
        if not self.manager.remove_rule_from_ruleset(ruleset_id, rule_id):
            return self.fail(
                f"Rule {rule_id} not found in rule set {ruleset_id}", 404
            )
        # Back to the standalone list, where it keeps its place in the order.
        rule.ruleset_id = None
        self.manager.add_rule(rule)
        self.write({"success": True})


class RuleSetReorderHandler(RewriteRequestHandler):
    """``POST /rewrite/rulesets/reorder`` -- set the order inside a set."""

    def post(self) -> None:
        body = self.json_body()
        ruleset_id = body.get("id")
        rule_ids = body.get("rule_ids")
        if not ruleset_id:
            return self.fail("id is required", 400)
        if not isinstance(rule_ids, list) or not all(
            isinstance(r, str) for r in rule_ids
        ):
            return self.fail("rule_ids must be a list of rule ids", 400)
        try:
            updated = self.manager.reorder_ruleset_rules(ruleset_id, rule_ids)
        except ValueError as e:
            return self.fail(str(e), 400)
        self.write({"success": True, "ruleset": updated.model_dump(exclude_none=True)})


class RuleSetMoveHandler(RewriteRequestHandler):
    """``POST /rewrite/rulesets/move`` -- move a set in the evaluation order."""

    def post(self) -> None:
        body = self.json_body()
        ruleset_id = body.get("id")
        index = body.get("index")
        if not ruleset_id:
            return self.fail("id is required", 400)
        if not isinstance(index, int):
            return self.fail("index must be an integer", 400)
        try:
            moved = self.manager.move_ruleset(ruleset_id, index)
        except ValueError as e:
            return self.fail(str(e), 400)
        self.write({"success": True, "ruleset": moved.model_dump(exclude_none=True)})


class RulePreviewHandler(RewriteRequestHandler):
    """``GET /rewrite/rules/preview`` -- who would win for one target field.

    The WebUI shows this in the rule editor: the rules that write the field
    the user picked, in evaluation order, the first one effective and the
    rest marked as skipped. The judgement is the engine's own: the same
    ``action_claims`` and ``claims_conflict`` the request path uses, so the
    preview cannot disagree with what actually happens on a flow.
    """

    def get(self) -> None:
        self.issue_xsrf_cookie()
        target = self.get_query_argument("target", None)
        field = self.get_query_argument("field", None)
        name = self.get_query_argument("name", None)
        if not target:
            return self.fail("target is required", 400)
        if not field:
            return self.fail("field is required", 400)

        try:
            probe = _preview_claim(target, field, name)
        except ValueError as e:
            return self.fail(str(e), 400)
        if probe is None:
            return self.fail(
                f"No such target field: {target} {field}"
                + (f" {name}" if name else ""),
                400,
            )

        # The same order the engine evaluates in: standalone rules first, then
        # each enabled set in order, rules inside a set in list order.
        rules = self.manager.list_rules()
        enabled_sets = {rs.id for rs in self.manager.list_rulesets() if rs.enabled}

        rows: list[dict[str, Any]] = []
        owner: str | None = None
        for rule in rules:
            if not rule.enabled:
                continue
            if rule.ruleset_id is not None and rule.ruleset_id not in enabled_sets:
                continue
            claims: list[tuple[str, str]] = []
            for action in rule.actions:
                claims.extend(action_claims(action))
            if not any(claims_conflict(claim, probe) for claim in claims):
                continue
            if owner is None:
                owner = rule.id
                rows.append(
                    {
                        "rule_id": rule.id,
                        "rule_name": rule.name,
                        "ruleset_id": rule.ruleset_id,
                        "effective": True,
                        "skipped_by": None,
                    }
                )
            else:
                rows.append(
                    {
                        "rule_id": rule.id,
                        "rule_name": rule.name,
                        "ruleset_id": rule.ruleset_id,
                        "effective": False,
                        "skipped_by": owner,
                    }
                )
        self.write({"success": True, "rules": rows})


def _preview_claim(
    target: str, field: str, name: str | None
) -> tuple[str, str] | None:
    """Turn a UI target field into the engine's own claim tuple.

    The result is comparable with ``claims_conflict``: a claim for
    ``request header x-foo`` is ``("request", "header:x-foo")``, matching what
    ``action_claims`` produces for a ``set_header`` action.
    """
    if target not in ("request", "response"):
        raise ValueError("target must be request or response")
    if field == "header":
        if not name:
            raise ValueError("name is required for a header field")
        return (target, f"header:{name.lower()}")
    if field == "query":
        if not name:
            raise ValueError("name is required for a query field")
        # Query names are case sensitive, so they are not lowercased.
        return (target, f"query:{name}")
    if field == "body":
        return (target, "body")
    if field in ("status_code", "method", "path", "url"):
        if field == "status_code":
            return ("response", "status_code")
        if field == "method":
            return ("request", "method")
        if field == "path":
            return ("request", "path")
        return ("request", "url")
    return None


def handlers(manager: ProxyManager) -> list[tuple[str, type[RewriteRequestHandler], dict[str, Any]]]:
    """The route table, bound to ``manager``.

    Split out from :func:`install` so tests can build a tornado application
    with the same settings the mitmweb one has, without a real proxy.
    """
    kwargs = {"manager": manager}
    return [  # type: ignore[return-value]
        (rf"{PREFIX}/pending", PendingHandler, kwargs),
        (rf"{PREFIX}/pending/decide", DecideHandler, kwargs),
        (rf"{PREFIX}/rules", RulesHandler, kwargs),
        (rf"{PREFIX}/rules/enable", RuleEnableHandler, kwargs),
        (rf"{PREFIX}/rules/delete", RuleDeleteHandler, kwargs),
        (rf"{PREFIX}/rulesets/enable", RuleSetEnableHandler, kwargs),
        (rf"{PREFIX}/rulesets$", RuleSetHandler, kwargs),
        (rf"{PREFIX}/rulesets/delete", RuleSetDeleteHandler, kwargs),
        (rf"{PREFIX}/rulesets/rules", RuleSetAddRuleHandler, kwargs),
        (rf"{PREFIX}/rulesets/rules/remove", RuleSetRemoveRuleHandler, kwargs),
        (rf"{PREFIX}/rulesets/reorder", RuleSetReorderHandler, kwargs),
        (rf"{PREFIX}/rulesets/move", RuleSetMoveHandler, kwargs),
        (rf"{PREFIX}/rules/preview", RulePreviewHandler, kwargs),
    ]


def install(manager: ProxyManager, master: WebMaster) -> None:
    """Mount the rewrite routes on the WebMaster's own tornado application."""
    master.app.add_handlers(r".*", handlers(manager))
    logger.info(
        "rewrite endpoints mounted on the mitmweb application at %s/*", PREFIX
    )
