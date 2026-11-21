"""Automatic rule engine for intercepting and modifying HTTP flows."""

from __future__ import annotations

import asyncio
import base64
import logging
import re
import threading
import time
import uuid
from typing import Any, Literal, Protocol
from urllib.parse import urlparse

from mitmproxy import connection
from mitmproxy import flowfilter
from mitmproxy import http
from mitmproxy.connection import ConnectionState
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, model_validator

from mitmproxy_mcp.events import EventBuffer

logger = logging.getLogger(__name__)


class Action(BaseModel):
    """A single action executed when a rule matches."""

    model_config = ConfigDict(extra="forbid")

    type: Literal[
        "set_header",
        "remove_header",
        "set_body",
        "replace_body",
        "set_status",
        "set_path",
        "set_method",
        "set_url",
        "set_query",
        "remove_query",
        "delay",
        "kill",
        "intercept",
        "resume",
        "cancel",
        "mark",
        "comment",
        "tag",
    ]

    # Common contextual fields
    target: Literal["request", "response"] | None = None

    # Header actions
    name: str | None = None
    value: str | None = None

    # Body actions
    content: str | None = None
    encoding: Literal["text", "base64"] = "text"
    pattern: str | None = None
    replacement: str | None = None

    # Response status
    status_code: int | None = None
    reason: str | None = None

    # Request line
    path: str | None = None
    method: str | None = None
    # Whole-URL replacement (scheme, host, port, path and query in one go).
    url: str | None = None

    # Delay
    seconds: float | None = None

    # Metadata
    marker: str | None = None
    comment: str | None = None
    tags: list[str] | None = None

    @model_validator(mode="after")
    def _check_required_fields(self) -> "Action":
        t = self.type

        if t in ("set_header", "remove_header"):
            if self.target is None:
                raise ValueError(f"Action '{t}' requires 'target'")
            if not self.name:
                raise ValueError(f"Action '{t}' requires 'name'")

        if t == "set_header" and self.value is None:
            raise ValueError("Action 'set_header' requires 'value'")

        if t == "set_body":
            if self.target is None:
                raise ValueError("Action 'set_body' requires 'target'")
            if self.content is None:
                raise ValueError("Action 'set_body' requires 'content'")

        if t == "replace_body":
            if self.target is None:
                raise ValueError("Action 'replace_body' requires 'target'")
            if self.pattern is None or self.replacement is None:
                raise ValueError("Action 'replace_body' requires 'pattern' and 'replacement'")

        if t == "set_status":
            if self.status_code is None:
                raise ValueError("Action 'set_status' requires 'status_code'")

        if t == "set_path" and self.path is None:
            raise ValueError("Action 'set_path' requires 'path'")

        if t == "set_method" and self.method is None:
            raise ValueError("Action 'set_method' requires 'method'")

        if t == "set_url":
            if not self.url:
                raise ValueError("Action 'set_url' requires 'url'")
            parsed = urlparse(self.url)
            if not parsed.scheme or not parsed.netloc:
                raise ValueError(
                    "Action 'set_url' requires an absolute URL "
                    "(scheme and host, e.g. 'https://example.com/path?a=1')"
                )

        # Query parameters live on the request, so these two actions are
        # request-only.  Accept an omitted target and target='request'; reject
        # target='response' instead of silently writing to the wrong message.
        if t in ("set_query", "remove_query"):
            if self.target == "response":
                raise ValueError(
                    f"Action '{t}' operates on the request query string; "
                    "use target='request' or omit target"
                )
            if not self.name:
                raise ValueError(f"Action '{t}' requires 'name'")
            if t == "set_query" and self.value is None:
                raise ValueError("Action 'set_query' requires 'value'")

        if t == "delay" and self.seconds is None:
            raise ValueError("Action 'delay' requires 'seconds'")

        if t == "mark" and self.marker is None:
            raise ValueError("Action 'mark' requires 'marker'")

        if t == "comment" and self.comment is None:
            raise ValueError("Action 'comment' requires 'comment'")

        if t == "tag" and self.tags is None:
            raise ValueError("Action 'tag' requires 'tags'")

        return self


PENDING_TTL_SECONDS = 300
"""How long a held flow waits for a decision before it is dropped, in seconds.

Five minutes. The REQ-6.1 acceptance line is "the queue clears itself once the
pending token expires or the client disconnects"; before this, an abandoned
hold stayed in ``GET /rewrite/pending`` and in the WebUI panel forever, and the
request sat on an open client connection with nothing left to release it.
"""

PENDING_EXPIRED_MESSAGE = "待决策已过期（TTL 5 分钟），已自动清理"
PENDING_CLIENT_DISCONNECTED_MESSAGE = "客户端已断开，待决策已取消"

_REMOVED_REASONS_MAX = 64
"""How many cleaned-up tokens are remembered for a better decide() answer."""


class PendingGone(KeyError):
    """A token that is no longer in the queue.

    Subclasses ``KeyError`` on purpose: every existing caller already handles
    "no such pending decision" that way, so a late decide() keeps answering
    ``success: false`` -- it only gets a truthful reason now.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message

    def __str__(self) -> str:  # KeyError would add its own quotes
        return self.message


Decision = Literal["execute", "abort", "cancel"]
"""Outcome of a manual decision on a held (intercepted) flow.

execute: apply the pending edits and release the flow.
abort:   drop the flow without forwarding it (flow marked aborted).
cancel:  discard the pending edits and release the flow unchanged.
"""


class PendingDecision(BaseModel):
    """A flow held for a manual decision, addressed by a pending token."""

    model_config = ConfigDict(extra="forbid")

    token: str
    flow_id: str
    """mitmproxy's native flow id (a UUID string), e.g. '07e1f32d-977a-...'."""

    store_id: int | None = None
    """u33pk FlowStore id when the flow has already been captured, else None."""

    rule_id: str
    rule_name: str = ""
    """Name of the rule that held the flow, captured when it was held.

    The WebUI shows it next to the pending entry and in the "rule is still
    enabled" notice after a cancel, so it has to survive a later rename.
    """

    phase: Literal["request", "response"]
    host: str = ""
    path: str = ""
    method: str = ""
    created_at: int
    """When the flow was held, as epoch seconds (integer).

    One unit everywhere: the WebUI panel renders this value directly, and a
    float here would silently be read as milliseconds by some clients.
    """

    expire_at: int = 0
    """When this entry is dropped automatically, as epoch seconds.

    ``created_at + PENDING_TTL_SECONDS``. 0 means "not computed yet" and is
    filled in by :meth:`RulesAddon._hold`; the WebUI counts down to it.
    """

    state: Literal["pending"] = "pending"
    """Lifecycle marker of a listed entry.

    Listed entries are by definition still waiting, so this is always
    "pending"; an entry that expired or whose client disconnected is removed
    from the queue and never listed again. The field exists so the WebUI can
    tell a held row from a future state without guessing.
    """


class Rule(BaseModel):
    """A rule that matches flows and applies actions automatically."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=1)
    name: str = ""
    enabled: bool = True
    ruleset_id: str | None = None
    """Owning rule set, or None for a standalone rule.

    A rule that belongs to a set is stored inside that set only; the set's own
    order decides its position in the evaluation order.
    """
    phase: Literal["request", "response", "both"] = "both"
    filter: str = Field(..., min_length=1)
    actions: list[Action] = Field(default_factory=list)
    decision: Decision = "execute"
    """Outcome applied when this rule holds a flow for a manual decision.

    Only meaningful for rules whose actions include "intercept".
    """

    _compiled_filter: flowfilter.TFilter | None = PrivateAttr(default=None)

    def model_post_init(self, __context: Any) -> None:
        action_types = {a.type for a in self.actions}
        if "cancel" in action_types and "intercept" in action_types:
            raise ValueError(
                "Action 'cancel' cannot be combined with 'intercept': cancel "
                "discards the rewrite and releases the flow, while intercept "
                "holds it for a manual decision."
            )
        if "resume" in action_types and "intercept" in action_types:
            raise ValueError(
                "Action 'resume' cannot be combined with 'intercept': resume "
                "releases the flow immediately, while intercept holds it for a "
                "manual decision."
            )
        try:
            self._compiled_filter = flowfilter.parse(self.filter)
        except ValueError as e:
            raise ValueError(f"Invalid filter expression '{self.filter}': {e}") from e

    def matches(self, flow: http.HTTPFlow, phase: str) -> bool:
        if not self.enabled:
            return False
        if self.phase != "both" and self.phase != phase:
            return False
        if self._compiled_filter is None:
            return False
        try:
            return bool(self._compiled_filter(flow))
        except Exception as e:
            logger.warning(f"Rule '{self.id}' filter evaluation failed: {e}")
            return False


def _decode_content(content: str, encoding: Literal["text", "base64"]) -> bytes:
    if encoding == "base64":
        return base64.b64decode(content)
    return content.encode("utf-8")


class RuleSet(BaseModel):
    """A named, orderable group of rules with one master on/off switch.

    Evaluation order: rule sets in the order they were added, then the rules
    inside each set in list order. Standalone rules (``ruleset_id`` is None)
    are evaluated first, in their own insertion order, so adding a set never
    reorders or re-prioritises rules that existed before rule sets did.
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=1)
    name: str = ""
    enabled: bool = True
    rules: list[Rule] = Field(default_factory=list)

    def model_post_init(self, __context: Any) -> None:
        seen: set[str] = set()
        for rule in self.rules:
            if rule.id in seen:
                raise ValueError(
                    f"Rule set '{self.id}' contains duplicate rule id '{rule.id}'"
                )
            seen.add(rule.id)
            # Membership is defined by containment: a rule inside a set belongs
            # to that set, whatever its ruleset_id said when it was built.
            rule.ruleset_id = self.id


FIELD_HEADER = "header"
FIELD_BODY = "body"
FIELD_STATUS = "status_code"
FIELD_METHOD = "method"
FIELD_PATH = "path"
FIELD_QUERY = "query"
FIELD_URL = "url"

#: Metadata key where the engine records rules whose writes were skipped
#: because another rule already claimed the same (target, field).
SKIPPED_KEY = "mitmproxy_mcp_rules_skipped"
#: Metadata key listing the rules that did apply.
APPLIED_KEY = "mitmproxy_mcp_rules_applied"

SKIP_REASON_FIELD_CLAIMED = "field_already_claimed"

#: Claim used by ``set_url`` for "every query parameter".
_QUERY_ANY = "query:*"


def action_claims(action: Action) -> list[tuple[str, str]]:
    """Return the (target, field) claims an action makes, or [] if it writes nothing.

    "First match wins, no stacking" works on this pair: the first rule that
    writes a (target, field) owns it for the flow, and every later write to the
    same pair is skipped rather than overwriting or appending.

    Field names:
      * ``header:<lowercased name>`` -- one header; request and response
        header of the same name are two different fields.
      * ``body`` -- set_body / replace_body on one message.
      * ``query:<name>`` -- one query parameter; different parameters do not
        conflict, so two rules may set ``a`` and ``b`` independently.
      * ``path``, ``method``, ``status_code``, ``url``.
    ``set_url`` rewrites the whole request line, so it claims ``url``,
    ``path`` and every query parameter (``query:*``).
    """
    t = action.type
    if t in ("set_header", "remove_header"):
        assert action.target is not None and action.name
        return [(action.target, f"{FIELD_HEADER}:{action.name.lower()}")]
    if t in ("set_body", "replace_body"):
        assert action.target is not None
        return [(action.target, FIELD_BODY)]
    if t == "set_status":
        return [("response", FIELD_STATUS)]
    if t == "set_method":
        return [("request", FIELD_METHOD)]
    if t == "set_path":
        return [("request", FIELD_PATH)]
    if t in ("set_query", "remove_query"):
        assert action.name
        return [("request", f"{FIELD_QUERY}:{action.name}")]
    if t == "set_url":
        return [
            ("request", FIELD_URL),
            ("request", FIELD_PATH),
            ("request", _QUERY_ANY),
        ]
    return []


def claims_conflict(a: tuple[str, str], b: tuple[str, str]) -> bool:
    """True when two claims name the same writable slot."""
    if a == b:
        return True
    # A whole-URL write covers the path and every query parameter.
    if a == ("request", FIELD_URL) and b[0] == "request" and b[1] in (
        FIELD_PATH,
        FIELD_URL,
    ):
        return True
    if b == ("request", FIELD_URL) and a[0] == "request" and a[1] in (
        FIELD_PATH,
        FIELD_URL,
    ):
        return True
    if a[1] == _QUERY_ANY and b[0] == "request" and b[1].startswith(f"{FIELD_QUERY}:"):
        return True
    if b[1] == _QUERY_ANY and a[0] == "request" and a[1].startswith(f"{FIELD_QUERY}:"):
        return True
    return False


def _owner_of(
    claims: list[tuple[str, str]], claimed: list[tuple[tuple[str, str], str]]
) -> tuple[tuple[str, str], str] | None:
    """Return (conflicting claim, owning rule id) if any claim is already taken."""
    for claim in claims:
        for existing, owner_rule_id in claimed:
            if claims_conflict(claim, existing):
                return existing, owner_rule_id
    return None


def _claim_label(claim: tuple[str, str]) -> dict[str, str]:
    """Human/UI-readable form of a claim, for the skip record."""
    target, field = claim
    if ":" in field:
        kind, _, name = field.partition(":")
        if kind == FIELD_HEADER:
            return {"target": target, "field": FIELD_HEADER, "name": name}
        if kind == FIELD_QUERY:
            return {"target": target, "field": FIELD_QUERY, "name": name}
    return {"target": target, "field": field}


#: Every action type the engine understands, in the order the docs list them.
ACTION_TYPES: tuple[str, ...] = (
    "set_header",
    "remove_header",
    "set_body",
    "replace_body",
    "set_status",
    "set_path",
    "set_method",
    "set_url",
    "set_query",
    "remove_query",
    "delay",
    "kill",
    "intercept",
    "resume",
    "cancel",
    "mark",
    "comment",
    "tag",
)

#: Fields each action type reads and writes, for a UI that builds editors.
ACTION_FIELDS: dict[str, dict[str, list[str]]] = {
    "set_header": {
        "required": ["type", "target", "name", "value"],
        "optional": [],
        "writes": ["header:<name>"],
    },
    "remove_header": {
        "required": ["type", "target", "name"],
        "optional": [],
        "writes": ["header:<name>"],
    },
    "set_body": {
        "required": ["type", "target", "content"],
        "optional": ["encoding (text|base64, default text)"],
        "writes": ["body"],
    },
    "replace_body": {
        "required": ["type", "target", "pattern", "replacement"],
        "optional": [],
        "writes": ["body"],
    },
    "set_status": {
        "required": ["type", "status_code"],
        "optional": ["reason"],
        "writes": ["response.status_code"],
    },
    "set_path": {
        "required": ["type", "path"],
        "optional": [],
        "writes": ["request.path"],
    },
    "set_method": {
        "required": ["type", "method"],
        "optional": [],
        "writes": ["request.method"],
    },
    "set_url": {
        "required": ["type", "url"],
        "optional": [],
        "writes": ["request.url", "request.path", "request.query:*"],
    },
    "set_query": {
        "required": ["type", "name", "value"],
        "optional": ["target ('request' only; may be omitted)"],
        "writes": ["request.query:<name>"],
    },
    "remove_query": {
        "required": ["type", "name"],
        "optional": ["target ('request' only; may be omitted)"],
        "writes": ["request.query:<name>"],
    },
    "delay": {"required": ["type", "seconds"], "optional": [], "writes": []},
    "kill": {"required": ["type"], "optional": [], "writes": []},
    "intercept": {"required": ["type"], "optional": [], "writes": []},
    "resume": {"required": ["type"], "optional": [], "writes": []},
    "cancel": {"required": ["type"], "optional": [], "writes": []},
    "mark": {"required": ["type", "marker"], "optional": [], "writes": []},
    "comment": {"required": ["type", "comment"], "optional": [], "writes": []},
    "tag": {"required": ["type", "tags"], "optional": [], "writes": []},
}

RULESET_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["id"],
    "properties": {
        "id": {"type": "string"},
        "name": {"type": "string", "default": ""},
        "enabled": {"type": "boolean", "default": True},
        "rules": {
            "type": "array",
            "description": "Rules inside the set, in evaluation order.",
            "items": {"$ref": "Rule"},
        },
    },
}

SKIPPED_RECORD_FIELDS: dict[str, str] = {
    "rule_id": "id of the rule whose write was skipped",
    "rule_name": "that rule's name, for display",
    "ruleset_id": "owning rule set id, or null",
    "action_type": "the action type that was skipped",
    "reason": "why it was skipped (currently 'field_already_claimed')",
    "field": "{target, field, name?} of the field that was already taken",
    "claimed_by": "id of the rule that took the field first",
    "phase": "'request' or 'response'",
}


def rule_contract() -> dict[str, Any]:
    """Machine-readable description of the rule engine's contract."""
    return {
        "success": True,
        "action_types": list(ACTION_TYPES),
        "action_fields": ACTION_FIELDS,
        "ruleset_schema": RULESET_SCHEMA,
        "evaluation_order": (
            "standalone rules in insertion order, then each enabled rule set in "
            "the order it was added, rules inside a set in list order"
        ),
        "conflict_policy": (
            "first match wins, no stacking: the first rule to write a "
            "(target, field) owns it for the flow; later writes to the same "
            "field are skipped and recorded"
        ),
        "skipped_metadata_key": SKIPPED_KEY,
        "applied_metadata_key": APPLIED_KEY,
        "skipped_record_fields": SKIPPED_RECORD_FIELDS,
        "skip_reasons": [SKIP_REASON_FIELD_CLAIMED],
    }


class FlowController(Protocol):
    """Releases or kills a held flow inside mitmproxy's own event loop."""

    def resume(self, flow: http.HTTPFlow) -> None: ...

    def kill(self, flow: http.HTTPFlow) -> None: ...

    def kill_and_wake(self, flow: http.HTTPFlow) -> None: ...


class RulesAddon:
    """mitmproxy addon that applies user-defined rules to live flows."""

    #: How often the background reaper looks for expired and abandoned holds,
    #: in seconds. Short enough that a 5 minute TTL is honoured to the second
    #: and that a killed client frees its row within a beat, cheap enough that
    #: it costs nothing when the queue is empty.
    reaper_interval: float = 1.0

    def __init__(
        self,
        event_buffer: EventBuffer | None = None,
        flow_controller: FlowController | None = None,
        *,
        pending_ttl: int = PENDING_TTL_SECONDS,
        reaper_interval: float | None = None,
        start_reaper: bool | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._rules: list[Rule] = []
        self._rulesets: list[RuleSet] = []
        self._event_buffer = event_buffer
        self._pending_ttl = int(pending_ttl)
        if reaper_interval is not None:
            self.reaper_interval = float(reaper_interval)
        # token -> why it left the queue, so a decide() that arrives late can
        # say "expired" or "client disconnected" instead of "unknown token".
        self._removed: dict[str, str] = {}
        # Guards the reaper thread's lifetime. The thread itself only wakes up
        # to look at `_pending`; it starts lazily (see _ensure_reaper) so a
        # RulesAddon built in a unit test does not leave a thread behind.
        # None means "only when a FlowController is attached", i.e. only inside
        # a running proxy: without one there is nothing a reaper could kill.
        self._reaper_stop: threading.Event | None = None
        self._reaper_thread: threading.Thread | None = None
        self._start_reaper = start_reaper
        # Releases a held flow. mitmproxy runs in its own event loop thread, so
        # flow.resume() must be dispatched there: asyncio.Event.set() from a
        # foreign thread does not wake the waiter.
        self._flow_controller = flow_controller
        # token -> (PendingDecision, flow, original_request, original_response, loop)
        #
        # `loop` is the proxy's own event loop, captured while the flow is
        # held (the hook runs inside that loop).  The decision arrives later
        # on the MCP thread, and asyncio.Event.set() from a foreign thread
        # does not wake a waiter parked in the proxy's loop -- so the loop has
        # to be remembered to be able to hop back onto it.
        self._pending: dict[
            str,
            tuple[
                PendingDecision,
                http.HTTPFlow,
                http.Request | None,
                http.Response | None,
                asyncio.AbstractEventLoop | None,
            ],
        ] = {}

    # ------------------------------------------------------------------
    # Rule management (called from the MCP tool thread)
    # ------------------------------------------------------------------

    def list_rules(self) -> list[Rule]:
        """All rules in evaluation order: standalone rules first, then each set."""
        with self._lock:
            ordered = list(self._rules)
            for ruleset in self._rulesets:
                ordered.extend(ruleset.rules)
            return ordered

    def add_rule(self, rule: Rule) -> None:
        with self._lock:
            if rule.ruleset_id is not None:
                ruleset = self._find_ruleset(rule.ruleset_id)
                if ruleset is None:
                    raise ValueError(f"Rule set '{rule.ruleset_id}' not found")
                self._drop_rule_everywhere(rule.id)
                ruleset.rules.append(rule)
                return
            # Replace existing rule with same id.
            self._rules = [r for r in self._rules if r.id != rule.id]
            self._rules.append(rule)

    def update_rule(self, rule_id: str, updates: dict[str, Any]) -> Rule | None:
        with self._lock:
            for container in self._rule_containers():
                for idx, existing in enumerate(container):
                    if existing.id != rule_id:
                        continue
                    data = existing.model_dump()
                    data.update(updates)
                    # Re-validate filter by creating a new Rule.
                    new_rule = Rule(**data)
                    container[idx] = new_rule
                    # Moving a rule between containers is done by ruleset add /
                    # remove, not by update; keep membership consistent here.
                    if new_rule.ruleset_id != existing.ruleset_id:
                        new_rule.ruleset_id = existing.ruleset_id
                    return new_rule
        return None

    def delete_rule(self, rule_id: str) -> bool:
        with self._lock:
            before = len(self.list_rules())
            self._drop_rule_everywhere(rule_id)
            return len(self.list_rules()) < before

    def clear_rules(self) -> int:
        """Delete every rule and every rule set.

        A rule set with no rules left is only clutter, and "clear" is what a
        user or a test fixture means by resetting the rule configuration.
        """
        with self._lock:
            count = len(self.list_rules())
            self._rules.clear()
            self._rulesets.clear()
            return count

    # ------------------------------------------------------------------
    # Rule sets
    # ------------------------------------------------------------------

    def list_rulesets(self) -> list[RuleSet]:
        """Rule sets in evaluation order."""
        with self._lock:
            return list(self._rulesets)

    def get_ruleset(self, ruleset_id: str) -> RuleSet | None:
        with self._lock:
            ruleset = self._find_ruleset(ruleset_id)
            return ruleset.model_copy(deep=True) if ruleset is not None else None

    def add_ruleset(self, ruleset: RuleSet) -> RuleSet:
        """Add or replace a rule set by id.

        Replacing keeps the set's existing position in the evaluation order:
        the WebUI edits a set in place and must not silently re-prioritise it.
        """
        with self._lock:
            for idx, existing in enumerate(self._rulesets):
                if existing.id == ruleset.id:
                    self._rulesets[idx] = ruleset
                    # Rule ids may have moved into this set from elsewhere.
                    for rule in ruleset.rules:
                        self._drop_rule_everywhere(rule.id, keep_container=ruleset.rules)
                    return self._rulesets[idx]
            self._rulesets.append(ruleset)
            for rule in ruleset.rules:
                self._drop_rule_everywhere(rule.id, keep_container=ruleset.rules)
            return self._rulesets[-1]

    def update_ruleset(self, ruleset_id: str, updates: dict[str, Any]) -> RuleSet | None:
        with self._lock:
            for idx, existing in enumerate(self._rulesets):
                if existing.id != ruleset_id:
                    continue
                data = existing.model_dump()
                data.update(updates)
                # Rules are managed by the rule commands, not by set update.
                data["rules"] = existing.model_dump()["rules"]
                new_set = RuleSet(**data)
                self._rulesets[idx] = new_set
                return new_set
        return None

    def delete_ruleset(self, ruleset_id: str) -> bool:
        """Delete a set and the rules inside it."""
        with self._lock:
            for idx, existing in enumerate(self._rulesets):
                if existing.id == ruleset_id:
                    del self._rulesets[idx]
                    return True
        return False

    def set_ruleset_enabled(self, ruleset_id: str, enabled: bool) -> RuleSet | None:
        with self._lock:
            for ruleset in self._rulesets:
                if ruleset.id == ruleset_id:
                    ruleset.enabled = enabled
                    return ruleset
        return None

    def add_rule_to_ruleset(
        self, ruleset_id: str, rule: Rule, index: int | None = None
    ) -> RuleSet | None:
        """Put a rule inside a set, optionally at a given position."""
        with self._lock:
            ruleset = self._find_ruleset(ruleset_id)
            if ruleset is None:
                return None
            self._drop_rule_everywhere(rule.id)
            rule.ruleset_id = ruleset_id
            if index is None:
                ruleset.rules.append(rule)
            else:
                if index < 0 or index > len(ruleset.rules):
                    raise ValueError(
                        f"index {index} out of range for rule set '{ruleset_id}' "
                        f"(0..{len(ruleset.rules)})"
                    )
                ruleset.rules.insert(index, rule)
            return ruleset

    def remove_rule_from_ruleset(self, ruleset_id: str, rule_id: str) -> bool:
        with self._lock:
            ruleset = self._find_ruleset(ruleset_id)
            if ruleset is None:
                return False
            before = len(ruleset.rules)
            ruleset.rules = [r for r in ruleset.rules if r.id != rule_id]
            return len(ruleset.rules) < before

    def reorder_ruleset_rules(self, ruleset_id: str, rule_ids: list[str]) -> RuleSet:
        """Set the order of rules inside one set.

        Every rule in the set has to be named exactly once: a partial order
        would silently drop rules from the set.
        """
        with self._lock:
            ruleset = self._find_ruleset(ruleset_id)
            if ruleset is None:
                raise ValueError(f"Rule set '{ruleset_id}' not found")
            by_id = {r.id: r for r in ruleset.rules}
            if set(rule_ids) != set(by_id) or len(rule_ids) != len(by_id):
                missing = sorted(set(by_id) - set(rule_ids))
                unknown = sorted(set(rule_ids) - set(by_id))
                raise ValueError(
                    "rule_ids must list every rule in the set exactly once "
                    f"(missing={missing}, unknown={unknown})"
                )
            ruleset.rules = [by_id[rid] for rid in rule_ids]
            return ruleset

    def move_ruleset(self, ruleset_id: str, index: int) -> RuleSet:
        """Move a whole set to a new position in the evaluation order."""
        with self._lock:
            for idx, ruleset in enumerate(self._rulesets):
                if ruleset.id != ruleset_id:
                    continue
                if index < 0 or index >= len(self._rulesets):
                    raise ValueError(
                        f"index {index} out of range (0..{len(self._rulesets) - 1})"
                    )
                del self._rulesets[idx]
                self._rulesets.insert(index, ruleset)
                return ruleset
        raise ValueError(f"Rule set '{ruleset_id}' not found")

    def _find_ruleset(self, ruleset_id: str | None) -> RuleSet | None:
        if ruleset_id is None:
            return None
        for ruleset in self._rulesets:
            if ruleset.id == ruleset_id:
                return ruleset
        return None

    def _rule_containers(self) -> list[list[Rule]]:
        """Every list that can hold a rule: the standalone list and each set."""
        return [self._rules] + [ruleset.rules for ruleset in self._rulesets]

    def _drop_rule_everywhere(
        self, rule_id: str, keep_container: list[Rule] | None = None
    ) -> None:
        for container in self._rule_containers():
            if container is keep_container:
                continue
            container[:] = [r for r in container if r.id != rule_id]

    # ------------------------------------------------------------------
    # Pending decisions (manual hold / release)
    # ------------------------------------------------------------------

    def list_pending(self) -> list[PendingDecision]:
        """Return the flows currently held for a manual decision.

        Reading the queue also sweeps it: entries past their TTL or whose
        client is gone are dropped here, so a panel that polls this endpoint
        can never show a hold the engine has already given up on, even if the
        background reaper thread is not running (a unit test, say).
        """
        self._sweep_pending()
        with self._lock:
            entries = [entry[0] for entry in self._pending.values()]
        # expire_at is derived, and re-derived on read so a snapshot taken
        # before the field existed still reports an honest deadline.
        for decision in entries:
            if not decision.expire_at:
                decision.expire_at = decision.created_at + self._pending_ttl
        return entries

    # -- pending queue cleanup (TTL + client disconnect) -----------------

    def pending_ttl(self) -> int:
        """The TTL this engine applies, in seconds (300 in production)."""
        return self._pending_ttl

    def set_pending_ttl(self, seconds: int) -> None:
        """Change the TTL for holds made from now on.

        Only tests and an operator tuning a single engine call this; the
        production default stays ``PENDING_TTL_SECONDS``. Entries already in
        the queue keep the ``expire_at`` computed when they were held.
        """
        seconds = int(seconds)
        if seconds <= 0:
            raise ValueError("pending TTL must be positive")
        with self._lock:
            self._pending_ttl = seconds

    def _ensure_reaper(self) -> None:
        """Start the background reaper once, on first hold."""
        with self._lock:
            if self._reaper_thread is not None and self._reaper_thread.is_alive():
                return
            if self._reaper_stop is None:
                self._reaper_stop = threading.Event()
            stop = self._reaper_stop
            thread = threading.Thread(
                target=self._reaper_loop,
                args=(stop,),
                name="u33pk-pending-reaper",
                daemon=True,
            )
            self._reaper_thread = thread
        thread.start()

    def stop_reaper(self) -> None:
        """Stop the background reaper (idempotent)."""
        with self._lock:
            stop = self._reaper_stop
            thread = self._reaper_thread
            self._reaper_thread = None
            self._reaper_stop = None
        if stop is not None:
            stop.set()
        if thread is not None and thread.is_alive():
            thread.join(timeout=2)

    def _reaper_loop(self, stop: threading.Event) -> None:
        while not stop.wait(self.reaper_interval):
            try:
                self._sweep_pending()
            except Exception:  # noqa: BLE001 - a reaper never dies on one bad entry
                logger.exception("pending reaper sweep failed")

    def _sweep_pending(self) -> list[str]:
        """Drop expired and abandoned holds; return the tokens removed.

        Two reasons, both ending the same way -- the flow is killed so the
        client connection is closed and nothing is forwarded upstream:

        * ``expired``: nobody decided within ``_pending_ttl`` seconds.
        * ``client_disconnected``: the client hung up while the flow was held.

        Must stay cheap: the reaper calls it once a second.
        """
        now = time.time()
        expired: list[tuple[str, PendingDecision, object, object]] = []
        abandoned: list[tuple[str, PendingDecision, object, object]] = []
        with self._lock:
            for token, entry in list(self._pending.items()):
                decision, flow, _req, _resp, flow_loop = entry
                if not decision.expire_at:
                    # An entry queued before this field existed: derive it
                    # rather than treat 0 as "expired long ago".
                    decision.expire_at = decision.created_at + self._pending_ttl
                ttl_left = decision.expire_at - now
                if ttl_left <= 0:
                    expired.append((token, decision, flow, flow_loop))
                elif self._client_gone(flow):
                    abandoned.append((token, decision, flow, flow_loop))
            for token, _d, _flow, _loop in expired + abandoned:
                if token in self._pending:
                    del self._pending[token]
        for token, decision, flow, flow_loop in expired:
            self._finish_removed(token, decision, flow, flow_loop, "expired")
        for token, decision, flow, flow_loop in abandoned:
            self._finish_removed(
                token, decision, flow, flow_loop, "client_disconnected"
            )
        return [token for token, _d, _f, _l in expired + abandoned]

    @staticmethod
    def _client_gone(flow: http.HTTPFlow) -> bool:
        """True when the client side of a held flow is known to be closed.

        One signal, read off the flow itself: the flow is still ``live`` but
        its client connection lost ``CAN_READ``. mitmproxy clears that bit in
        the client's read loop, which is a task of its own, so the bit is
        already clear while the hook that holds the flow is still parked.

        Deliberately conservative: a flow that is not live, or whose
        connection state is unknown, counts as alive, so a false positive can
        never kill a request a user is still waiting for. The
        ``client_disconnected`` hook is the primary signal; this is only the
        safety net for the case where that hook never arrived.
        """
        if not getattr(flow, "live", False):
            return False
        client = getattr(flow, "client_conn", None)
        if client is None:
            return False
        state = getattr(client, "state", None)
        return state is not None and not (state & ConnectionState.CAN_READ)

    def _finish_removed(
        self,
        token: str,
        decision: PendingDecision,
        flow: http.HTTPFlow,
        flow_loop: asyncio.AbstractEventLoop | None,
        reason: str,
    ) -> None:
        """Kill a held flow that left the queue without a decision."""
        self._remember_removed(token, reason)
        try:
            # Same path as an abort: kill and wake in one loop tick, so the
            # parked hook returns and the client connection is closed instead
            # of hanging until its own timeout.
            self._kill_flow(flow, flow_loop)
        except Exception:  # noqa: BLE001 - the flow may already be gone
            logger.debug("could not kill abandoned flow %s", token, exc_info=True)
        flow.metadata = flow.metadata or {}
        flow.metadata["mitmproxy_mcp_decision"] = reason
        if self._event_buffer is not None:
            self._event_buffer.emit(
                "flow:decided",
                {
                    "token": token,
                    "flow_id": decision.flow_id,
                    "rule_id": decision.rule_id,
                    "decision": reason,
                    "reason": reason,
                },
            )

    def _remember_removed(self, token: str, reason: str) -> None:
        with self._lock:
            self._removed.pop(token, None)
            self._removed[token] = reason
            while len(self._removed) > _REMOVED_REASONS_MAX:
                self._removed.pop(next(iter(self._removed)))

    def removed_reason(self, token: str) -> str | None:
        """Why a token left the queue, when it did so without a decision."""
        with self._lock:
            return self._removed.get(token)

    def _hold(
        self,
        flow: http.HTTPFlow,
        rule_id: str,
        phase: str,
        original_request: http.Request | None = None,
        original_response: http.Response | None = None,
        rule_name: str = "",
    ) -> PendingDecision:
        """Hold a flow for a manual decision and return its pending token.

        The caller passes the snapshot taken *before* any rewrite action ran,
        so that a later "cancel" discards the edits and restores the original.
        """
        token = uuid.uuid4().hex
        store_id = None
        if flow.metadata:
            raw_store_id = flow.metadata.get("mitmproxy_mcp_id")
            if isinstance(raw_store_id, int):
                store_id = raw_store_id
        decision = PendingDecision(
            token=token,
            flow_id=flow.id,
            store_id=store_id,
            rule_id=rule_id,
            rule_name=rule_name,
            phase=phase,  # type: ignore[arg-type]
            host=flow.request.host,
            path=flow.request.path,
            method=flow.request.method,
            created_at=int(time.time()),
        )
        decision.expire_at = decision.created_at + self._pending_ttl
        # The hook that holds the flow runs inside the proxy's event loop.
        # Remember it: the decision comes later on the MCP thread.
        try:
            flow_loop = asyncio.get_running_loop()
        except RuntimeError:
            flow_loop = None
        with self._lock:
            self._pending[token] = (
                decision,
                flow,
                original_request,
                original_response,
                flow_loop,
            )
        if self._start_reaper is not False and (
            self._start_reaper or self._flow_controller is not None
        ):
            self._ensure_reaper()
        flow.intercept()
        if self._event_buffer is not None:
            self._event_buffer.emit(
                "flow:pending",
                {
                    "token": token,
                    "flow_id": flow.id,
                    "rule_id": rule_id,
                    "phase": phase,
                    "host": flow.request.host,
                    "path": flow.request.path,
                    "method": flow.request.method,
                },
            )
        return decision

    def _resume_flow(self, flow: http.HTTPFlow, loop: asyncio.AbstractEventLoop | None = None) -> None:
        """Release a held flow.

        mitmproxy runs in its own event loop thread; asyncio.Event.set() from
        the MCP thread does not wake the waiter, so dispatch into that loop.
        """
        if self._flow_controller is not None:
            self._flow_controller.resume(flow)
            return
        self._wake_in_flow_loop(flow, loop, kill=False)

    def _kill_flow(self, flow: http.HTTPFlow, loop: asyncio.AbstractEventLoop | None = None) -> None:
        """Kill a held flow and wake the coroutine waiting for it.

        Killing alone is not enough: mitmproxy's ``Flow.kill()`` clears the
        ``intercepted`` flag but never sets the flow's resume event, so the
        proxy's hook handler stays parked in ``wait_for_resume()`` and the
        client connection hangs instead of being closed.
        """
        if self._flow_controller is not None:
            self._flow_controller.kill_and_wake(flow)
            return
        self._wake_in_flow_loop(flow, loop, kill=True)

    def _wake_in_flow_loop(
        self,
        flow: http.HTTPFlow,
        loop: asyncio.AbstractEventLoop | None,
        kill: bool,
    ) -> None:
        """Wake a held flow without a flow controller.

        Fallback for a standalone ``RulesAddon`` (no ``FlowController``).
        ``asyncio.Event.set()`` is not thread-safe: calling it from the MCP
        thread does not wake a waiter parked in the proxy's event loop, and
        the client connection hangs until it times out. Hop onto the flow's
        own loop instead.
        """
        event = getattr(flow, "_resume_event", None)

        def _do() -> None:
            if kill:
                if flow.killable:
                    flow.kill()
                # kill() clears `intercepted` but never sets the event.
                if event is not None:
                    event.set()
            else:
                # resume() clears `intercepted` and sets the event itself.
                flow.resume()

        if event is None:
            # No waiter is parked on this flow, so nothing has to be woken.
            _do()
            return

        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None

        if loop is None or loop.is_closed():
            # No usable loop for this flow: act inline as a best effort.
            _do()
            return

        if running is loop:
            # Already in the flow's loop: do it here, do not dispatch and
            # wait for the loop we are currently occupying.
            _do()
            return

        async def _wake() -> None:
            _do()

        future = asyncio.run_coroutine_threadsafe(_wake(), loop)
        future.result(timeout=30)

    def decide(
        self, token: str, decision: Decision
    ) -> tuple[PendingDecision, http.HTTPFlow]:
        """Resolve a held flow with one of the three decisions.

        execute: release the flow (pending edits are applied by the caller).
        abort:   kill the flow, it is not forwarded.
        cancel:  discard pending edits and release the flow unchanged.
        """
        with self._lock:
            entry = self._pending.pop(token, None)
            reason = self._removed.get(token)
        if entry is None:
            # A token that expired or lost its client is gone on purpose: say
            # which, so the WebUI can drop the row with a real explanation
            # instead of "unknown token".
            if reason == "expired":
                raise PendingGone(PENDING_EXPIRED_MESSAGE)
            if reason == "client_disconnected":
                raise PendingGone(PENDING_CLIENT_DISCONNECTED_MESSAGE)
            raise KeyError(f"No pending decision for token {token}")
        pending, flow, original_request, original_response, flow_loop = entry

        if decision == "abort":
            # Killing also wakes the waiting handler: otherwise the client
            # connection hangs instead of being closed.
            self._kill_flow(flow, flow_loop)
            flow.metadata = flow.metadata or {}
            flow.metadata["mitmproxy_mcp_decision"] = "abort"
        elif decision == "cancel":
            # Discard pending edits: restore the original messages.
            flow.metadata = flow.metadata or {}
            flow.metadata["mitmproxy_mcp_decision"] = "cancel"
            if original_request is not None:
                flow.request = original_request
            if original_response is not None:
                flow.response = original_response
            self._resume_flow(flow, flow_loop)
        else:
            flow.metadata = flow.metadata or {}
            flow.metadata["mitmproxy_mcp_decision"] = "execute"
            self._resume_flow(flow, flow_loop)
        if self._event_buffer is not None:
            self._event_buffer.emit(
                "flow:decided",
                {
                    "token": token,
                    "flow_id": pending.flow_id,
                    "rule_id": pending.rule_id,
                    "decision": decision,
                },
            )
        return pending, flow

    # ------------------------------------------------------------------
    # mitmproxy hooks
    # ------------------------------------------------------------------

    async def request(self, flow: http.HTTPFlow) -> None:
        await self._process(flow, "request")

    async def response(self, flow: http.HTTPFlow) -> None:
        await self._process(flow, "response")

    def client_disconnected(self, client: connection.Client) -> None:
        """Drop holds whose client just hung up.

        mitmproxy fires this from the connection's own handler task (see
        ``proxy/server.py``: ``handle_client`` awaits the connection handler,
        then announces the disconnect), and that task does not park on a held
        flow -- the hook that holds the flow runs in its own task. So this
        arrives while the flow is still intercepted, which is exactly when the
        queue must clear itself.

        Synchronous on purpose: nothing here waits on the flow. The kill is
        dispatched into the flow's own loop by ``_kill_flow``.
        """
        client_id = getattr(client, "id", None)
        if not self._pending or client_id is None:
            return
        doomed: list[tuple[str, PendingDecision, object, object]] = []
        with self._lock:
            for token, entry in list(self._pending.items()):
                decision, flow, _req, _resp, flow_loop = entry
                held_client = getattr(flow, "client_conn", None)
                if getattr(held_client, "id", None) == client_id:
                    doomed.append((token, decision, flow, flow_loop))
            for token, _d, _flow, _loop in doomed:
                self._pending.pop(token, None)
        for token, decision, flow, flow_loop in doomed:
            self._finish_removed(
                token, decision, flow, flow_loop, "client_disconnected"
            )

    def error(self, flow: http.HTTPFlow) -> None:
        """Safety net for a client that vanished without the hook firing.

        ``decide()`` pops the entry before killing the flow, so an abort never
        reaches here with a token still queued.
        """
        if not self._pending:
            return
        flow_id = str(flow.id) if flow.id is not None else None
        doomed: list[tuple[str, PendingDecision, object, object]] = []
        with self._lock:
            for token, entry in list(self._pending.items()):
                decision, held_flow, _req, _resp, flow_loop = entry
                if str(held_flow.id) != flow_id:
                    continue
                # The client closing its side is what we clean up for. An
                # upstream error is not: the flow still has a live client
                # waiting for a decision.
                if not self._client_gone(held_flow):
                    continue
                doomed.append((token, decision, held_flow, flow_loop))
            for token, _d, _flow, _loop in doomed:
                self._pending.pop(token, None)
        for token, decision, held_flow, flow_loop in doomed:
            self._finish_removed(
                token, decision, held_flow, flow_loop, "client_disconnected"
            )

    async def _process(self, flow: http.HTTPFlow, phase: str) -> None:
        # Evaluation order: standalone rules first, then each enabled rule set
        # in the order it was added, rules inside a set in list order.
        with self._lock:
            rules: list[Rule] = list(self._rules)
            for ruleset in self._rulesets:
                if not ruleset.enabled:
                    continue
                rules.extend(ruleset.rules)

        applied_rule_ids: list[str] = []
        skipped: list[dict[str, Any]] = []
        # (target, field) claims taken by rules that already ran on this flow,
        # with the id of the rule that took them.
        # "First match wins, no stacking": a later write to a claimed field is
        # skipped, not merged.
        claimed: list[tuple[tuple[str, str], str]] = []

        for rule in rules:
            if not rule.matches(flow, phase):
                continue

            # Split the rule into the actions it may run and those blocked by
            # a claim an earlier rule took. Control actions never write a field
            # and are always allowed.
            runnable: list[Action] = []
            blocked: list[tuple[Action, tuple[str, str], str]] = []
            for action in rule.actions:
                claims = action_claims(action)
                # Only earlier *rules* can block an action. Inside one rule the
                # actions keep their own sequential order (an author writing
                # remove_header then set_header in one rule means both), which
                # is also what a rule did before conflict tracking existed.
                owner = _owner_of(claims, claimed) if claims else None
                if owner is not None:
                    conflict, owner_rule_id = owner
                    blocked.append((action, conflict, owner_rule_id))
                    continue
                runnable.append(action)

            for action, conflict, owner_rule_id in blocked:
                skipped.append(
                    {
                        "rule_id": rule.id,
                        "rule_name": rule.name,
                        "ruleset_id": rule.ruleset_id,
                        "action_type": action.type,
                        "reason": SKIP_REASON_FIELD_CLAIMED,
                        "field": _claim_label(conflict),
                        "claimed_by": owner_rule_id,
                        "phase": phase,
                    }
                )

            action_types = {a.type for a in rule.actions}
            wants_intercept = "intercept" in action_types
            wants_cancel = "cancel" in action_types
            # Snapshot before any rewrite so "cancel" can discard the edits.
            original_request = (
                flow.request.copy() if flow.request is not None else None
            )
            original_response = (
                flow.response.copy() if flow.response is not None else None
            )
            if runnable:
                # Apply action by action so a failed action does not leave a
                # field claim behind: later rules may still write a field that
                # nothing successfully wrote.
                try:
                    for action in runnable:
                        await self._apply_action(flow, action)
                        claimed.extend((claim, rule.id) for claim in action_claims(action))
                except Exception as e:
                    logger.warning(f"Rule '{rule.id}' actions failed: {e}")
                    if wants_intercept:
                        # A breakpoint rule must never fail open: if we cannot
                        # hold the flow for a decision, letting it through
                        # silently would hand traffic to the server that the
                        # user meant to inspect.
                        logger.error(
                            f"Rule '{rule.id}' requested intercept but the flow "
                            f"could not be held ({e}); killing it instead of "
                            f"releasing it"
                        )
                        self._kill_flow(flow)
                    continue
            elif not wants_intercept and not wants_cancel:
                # Every action this rule had was blocked: nothing was applied,
                # so the rule does not appear in the applied list.
                continue

            applied_rule_ids.append(rule.id)

            if wants_cancel:
                # Discard the rewrites this rule applied and release unchanged.
                if original_request is not None:
                    flow.request = original_request
                if original_response is not None:
                    flow.response = original_response
                if flow.metadata is None:
                    flow.metadata = {}
                flow.metadata["mitmproxy_mcp_decision"] = "cancel"
                continue

            if wants_intercept:
                try:
                    # Hold the flow for a manual decision.
                    self._hold(
                        flow,
                        rule.id,
                        phase,
                        original_request=original_request,
                        original_response=original_response,
                        rule_name=rule.name,
                    )
                except Exception as e:
                    # Never fail open on a breakpoint rule: kill the flow rather
                    # than release traffic the user meant to inspect.
                    logger.error(
                        f"Rule '{rule.id}' requested intercept but the flow could "
                        f"not be held ({e}); killing it instead of releasing it"
                    )
                    self._kill_flow(flow)
                break

        if applied_rule_ids or skipped:
            if flow.metadata is None:
                flow.metadata = {}
            if applied_rule_ids:
                flow.metadata.setdefault(APPLIED_KEY, []).extend(applied_rule_ids)
            if skipped:
                flow.metadata.setdefault(SKIPPED_KEY, []).extend(skipped)
        if applied_rule_ids:
            if self._event_buffer is not None:
                self._event_buffer.emit(
                    "rule:matched",
                    {
                        "rule_ids": applied_rule_ids,
                        "phase": phase,
                        "host": flow.request.host,
                        "path": flow.request.path,
                        "method": flow.request.method,
                    },
                )
        if skipped:
            if self._event_buffer is not None:
                self._event_buffer.emit(
                    "rule:skipped",
                    {
                        "skipped": skipped,
                        "phase": phase,
                        "host": flow.request.host,
                        "path": flow.request.path,
                        "method": flow.request.method,
                    },
                )

    async def _apply_actions(
        self, flow: http.HTTPFlow, actions: list[Action]
    ) -> None:
        for action in actions:
            await self._apply_action(flow, action)

    async def _apply_action(self, flow: http.HTTPFlow, action: Action) -> None:
        t = action.type

        if t == "set_header":
            target = self._get_message(flow, action.target)
            if target is not None:
                target.headers[action.name] = action.value
            return

        if t == "remove_header":
            target = self._get_message(flow, action.target)
            if target is not None:
                target.headers.pop(action.name, None)
            return

        if t == "set_body":
            target = self._get_message(flow, action.target)
            if target is not None:
                target.content = _decode_content(action.content, action.encoding)
            return

        if t == "replace_body":
            target = self._get_message(flow, action.target)
            if target is not None:
                pattern = action.pattern.encode("utf-8")
                replacement = action.replacement.encode("utf-8")
                target.content = re.sub(
                    pattern, replacement, target.content, flags=re.DOTALL
                )
            return

        if t == "set_status":
            if flow.response is None:
                flow.response = http.Response.make(
                    status_code=action.status_code,
                    content=b"",
                )
            flow.response.status_code = action.status_code
            if action.reason is not None:
                flow.response.reason = action.reason
            return

        if t == "set_path":
            flow.request.path = action.path
            return

        if t == "set_method":
            flow.request.method = action.method
            return

        if t == "set_url":
            # mitmproxy's Request.url setter parses scheme/host/port/path/query
            # and re-encodes them, so a URL with spaces or non-ASCII in it is
            # never pasted into the request line unescaped.
            flow.request.url = action.url
            return

        if t == "set_query":
            # MultiDictView encodes the name and value itself; hand-built
            # "?a=b&c=d" strings would corrupt values containing & = or spaces.
            flow.request.query[action.name] = action.value
            return

        if t == "remove_query":
            flow.request.query.pop(action.name, None)
            return

        if t == "delay":
            await asyncio.sleep(action.seconds)
            return

        if t == "kill":
            if flow.killable:
                flow.kill()
            return

        if t == "intercept":
            # The flow is held for a manual decision; the caller decides.
            return

        if t == "cancel":
            # Discard the rewrites this rule applied and release the flow
            # unchanged. The caller restores the pre-rule snapshot.
            return

        if t == "resume":
            flow.resume()
            return

        if t == "mark":
            flow.marked = action.marker
            return

        if t == "comment":
            flow.comment = action.comment
            return

        if t == "tag":
            if flow.metadata is None:
                flow.metadata = {}
            flow.metadata["tags"] = action.tags
            return

    @staticmethod
    def _get_message(
        flow: http.HTTPFlow, target: Literal["request", "response"] | None
    ) -> http.Request | http.Response | None:
        if target == "request":
            return flow.request
        if target == "response":
            return flow.response
        return None
