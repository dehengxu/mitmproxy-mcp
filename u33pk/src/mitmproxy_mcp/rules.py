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

from mitmproxy import flowfilter
from mitmproxy import http
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

        if t == "delay" and self.seconds is None:
            raise ValueError("Action 'delay' requires 'seconds'")

        if t == "mark" and self.marker is None:
            raise ValueError("Action 'mark' requires 'marker'")

        if t == "comment" and self.comment is None:
            raise ValueError("Action 'comment' requires 'comment'")

        if t == "tag" and self.tags is None:
            raise ValueError("Action 'tag' requires 'tags'")

        return self


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
    phase: Literal["request", "response"]
    created_at: float


class Rule(BaseModel):
    """A rule that matches flows and applies actions automatically."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=1)
    name: str = ""
    enabled: bool = True
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


class FlowController(Protocol):
    """Releases or kills a held flow inside mitmproxy's own event loop."""

    def resume(self, flow: http.HTTPFlow) -> None: ...

    def kill(self, flow: http.HTTPFlow) -> None: ...

    def kill_and_wake(self, flow: http.HTTPFlow) -> None: ...


class RulesAddon:
    """mitmproxy addon that applies user-defined rules to live flows."""

    def __init__(
        self,
        event_buffer: EventBuffer | None = None,
        flow_controller: FlowController | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._rules: list[Rule] = []
        self._event_buffer = event_buffer
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
        with self._lock:
            return list(self._rules)

    def add_rule(self, rule: Rule) -> None:
        with self._lock:
            # Replace existing rule with same id.
            self._rules = [r for r in self._rules if r.id != rule.id]
            self._rules.append(rule)

    def update_rule(self, rule_id: str, updates: dict[str, Any]) -> Rule | None:
        with self._lock:
            for idx, existing in enumerate(self._rules):
                if existing.id == rule_id:
                    data = existing.model_dump()
                    data.update(updates)
                    # Re-validate filter by creating a new Rule.
                    new_rule = Rule(**data)
                    self._rules[idx] = new_rule
                    return new_rule
        return None

    def delete_rule(self, rule_id: str) -> bool:
        with self._lock:
            before = len(self._rules)
            self._rules = [r for r in self._rules if r.id != rule_id]
            return len(self._rules) < before

    def clear_rules(self) -> int:
        with self._lock:
            count = len(self._rules)
            self._rules.clear()
            return count

    # ------------------------------------------------------------------
    # Pending decisions (manual hold / release)
    # ------------------------------------------------------------------

    def list_pending(self) -> list[PendingDecision]:
        """Return the flows currently held for a manual decision."""
        with self._lock:
            return [entry[0] for entry in self._pending.values()]

    def _hold(
        self,
        flow: http.HTTPFlow,
        rule_id: str,
        phase: str,
        original_request: http.Request | None = None,
        original_response: http.Response | None = None,
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
            phase=phase,  # type: ignore[arg-type]
            created_at=time.time(),
        )
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
        if entry is None:
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

    async def _process(self, flow: http.HTTPFlow, phase: str) -> None:
        with self._lock:
            rules = list(self._rules)

        applied_rule_ids: list[str] = []
        for rule in rules:
            if not rule.matches(flow, phase):
                continue
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
            try:
                await self._apply_actions(flow, rule.actions)
            except Exception as e:
                logger.warning(f"Rule '{rule.id}' actions failed: {e}")
                if wants_intercept:
                    # A breakpoint rule must never fail open: if we cannot hold
                    # the flow for a decision, letting it through silently would
                    # hand traffic to the server that the user meant to inspect.
                    logger.error(
                        f"Rule '{rule.id}' requested intercept but the flow could "
                        f"not be held ({e}); killing it instead of releasing it"
                    )
                    self._kill_flow(flow)
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

        if applied_rule_ids:
            if flow.metadata is None:
                flow.metadata = {}
            flow.metadata.setdefault("mitmproxy_mcp_rules_applied", []).extend(
                applied_rule_ids
            )
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
