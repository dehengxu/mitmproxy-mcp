"""Focus (REQ-4.2) -- pin hosts to the top of the flow list, everything else
into an "Other" group.

Focus is a *view reordering* semantic, not a filter:

* nothing is hidden, dropped or rewritten -- focused and non-focused traffic
  both stay in the recorder and in every listing;
* only the order and the grouping of the rendered list change;
* cancelling a focus restores the original order.

Filtering ("hide what does not match") lives in :class:`ScopeManager` and in
``search_traffic``.  The two are separate mechanisms and never share state:
:class:`FocusManager` never touches the scope config, and scope never reads
the focus set.

Host matching
-------------
Matching is **case-insensitive exact match** on the bare host name:

* both sides are normalised with :func:`normalize_host` -- strip surrounding
  whitespace, then lower-case;
* no subdomain wildcard (``api.example.com`` does not match
  ``eu.api.example.com``), no glob, no suffix match;
* the host is the bare name as mitmproxy reports it (``flow.request.host``,
  i.e. no scheme, no port, no trailing dot, no userinfo).  A value carrying a
  scheme or port is stored as given, so it will simply never match a flow;
* empty / whitespace-only entries are rejected instead of stored.

Storage
-------
The focus set is kept in a small JSON file (default ``mitm_mcp_focus.json`` in
the working directory, next to the traffic database) and is re-read from disk
on every access, so it survives process restarts and ``list_focus`` always
reports what is really stored.  Writes are atomic (temp file + ``os.replace``)
and serialised by a lock, so a torn file is impossible.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence
from urllib.parse import urlparse

#: Name of the group that collects every flow whose host is not focused.
OTHER_GROUP = "Other"

#: Default on-disk location, relative to the process working directory.
DEFAULT_FOCUS_FILE = "mitm_mcp_focus.json"

#: Environment variable that overrides the default location.
FOCUS_FILE_ENV = "MITMPROXY_MCP_FOCUS_FILE"


def normalize_host(host: str) -> str:
    """Return the canonical form used for both storing and matching a host.

    Strip surrounding whitespace, then lower-case.  Nothing else: no scheme,
    port or trailing-dot handling, and no wildcard expansion.
    """
    if not isinstance(host, str):
        raise TypeError("host must be a string")
    return host.strip().lower()


def default_focus_path() -> Path:
    override = os.environ.get(FOCUS_FILE_ENV)
    if override:
        return Path(override).expanduser()
    return Path(DEFAULT_FOCUS_FILE)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class FocusManager:
    """Persisted set of focused hosts, ordered as the user focused them."""

    def __init__(self, path: Optional[Path | str] = None):
        self._lock = threading.RLock()
        self._path = Path(path).expanduser() if path else default_focus_path()

    # -- paths -----------------------------------------------------------
    @property
    def path(self) -> Path:
        return self._path

    # -- disk ------------------------------------------------------------
    def _read(self) -> List[str]:
        try:
            raw = self._path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return []
        except OSError:
            return []
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            # A corrupt file must not take the tool down: start from empty and
            # let the next write repair it.
            return []

        if isinstance(data, dict):
            stored = data.get("focused_hosts")
        elif isinstance(data, list):
            stored = data
        else:
            return []
        if not isinstance(stored, list):
            return []

        ordered: List[str] = []
        for entry in stored:
            if not isinstance(entry, str):
                continue
            host = normalize_host(entry)
            if host and host not in ordered:
                ordered.append(host)
        return ordered

    def _write(self, hosts: Sequence[str]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload: Dict[str, Any] = {
            "focused_hosts": list(hosts),
            "other_group": OTHER_GROUP,
            "updated_at": _now(),
        }
        fd, tmp_name = tempfile.mkstemp(
            prefix=self._path.name + ".", suffix=".tmp", dir=str(self._path.parent)
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=False)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, self._path)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    # -- reads -----------------------------------------------------------
    def list_focus(self) -> List[str]:
        """Current focused hosts, in focus order (empty list when none)."""
        with self._lock:
            return self._read()

    def is_focused(self, host: str) -> bool:
        try:
            target = normalize_host(host)
        except TypeError:
            return False
        return bool(target) and target in self.list_focus()

    # -- writes ----------------------------------------------------------
    def focus(self, hosts: Iterable[str]) -> Dict[str, List[str]]:
        """Add hosts to the focus set (append semantics, idempotent).

        Returns ``{"added": [...], "already_focused": [...]}`` plus the
        resulting list under ``"focused_hosts"``.
        """
        if isinstance(hosts, str):
            hosts = [hosts]
        added: List[str] = []
        already: List[str] = []
        with self._lock:
            current = self._read()
            for entry in hosts:
                host = normalize_host(entry)
                if not host:
                    raise ValueError("host cannot be empty")
                if host in current:
                    if host not in already:
                        already.append(host)
                    continue
                current.append(host)
                added.append(host)
            if added:
                self._write(current)
            return {
                "focused_hosts": current,
                "other_group": OTHER_GROUP,
                "added": added,
                "already_focused": already,
            }

    def unfocus(self, host: str) -> Dict[str, Any]:
        """Remove one host from the focus set; a no-op when it was not focused."""
        target = normalize_host(host)
        if not target:
            raise ValueError("host cannot be empty")
        with self._lock:
            current = self._read()
            removed = target in current
            if removed:
                current = [h for h in current if h != target]
                self._write(current)
            return {
                "focused_hosts": current,
                "other_group": OTHER_GROUP,
                "removed": removed,
                "host": target,
            }

    def clear(self) -> None:
        """Drop every focus.  Not exposed as an MCP tool; used by tests."""
        with self._lock:
            self._write([])


def flow_host(flow: Any) -> str:
    """Bare host of a flow or of a flow-summary dict, normalised.

    Accepts an ``HTTPFlow`` (``request.host``) or a summary entry carrying a
    ``url``, so callers can group either representation.
    """
    request = getattr(flow, "request", None)
    host = getattr(request, "host", None) if request is not None else None
    if not host and isinstance(flow, dict):
        host = flow.get("host")
        if not host and flow.get("url"):
            host = urlparse(str(flow["url"])).hostname or ""
    return normalize_host(str(host or ""))


def group_by_focus(
    flows: Iterable[Any],
    focused_hosts: Sequence[str],
    host_getter=flow_host,
) -> List[Dict[str, Any]]:
    """Reorder ``flows`` into focus groups; never drop an entry.

    Groups come out in focus order (the order of ``focused_hosts``), with the
    ``Other`` group last.  A focused group with no matching flow is omitted, so
    the output holds exactly the flows that came in, in their original relative
    order inside each group.  This is the ordering the web UI renders; it is
    deliberately *not* a filter -- ``sum(len(g["flows"])) == len(flows)``.
    """
    focused = [normalize_host(h) for h in focused_hosts]
    focused = [h for h in focused if h]
    buckets: Dict[str, List[Any]] = {h: [] for h in focused}
    others: List[Any] = []
    for flow in flows:
        host = host_getter(flow)
        if host in buckets:
            buckets[host].append(flow)
        else:
            others.append(flow)

    groups: List[Dict[str, Any]] = [
        {"group": host, "focused": True, "flows": buckets[host]}
        for host in focused
        if buckets[host]
    ]
    if others:
        groups.append({"group": OTHER_GROUP, "focused": False, "flows": others})
    return groups
