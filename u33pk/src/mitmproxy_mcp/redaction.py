"""Default redaction policy: which fields are masked when a flow is shown.

This is a *display and export* policy only.  Nothing here touches the bytes
that are forwarded to the server or returned to the client: the proxy must
relay the real messages, including the credentials in them, or it would break
the traffic it is inspecting.

The lists live here, in one place, so the WebUI does not have to hard-code
them: read them with the ``redaction_policy`` tool or from ``tool_info``.
"""

from __future__ import annotations

from typing import Any, Literal

REDACTION_PLACEHOLDER = "«redacted»"

#: Header names masked wherever they appear (request or response).
#: Compared case-insensitively.
REDACTED_HEADERS: tuple[str, ...] = (
    "Authorization",
    "Cookie",
    "Set-Cookie",
    "Proxy-Authorization",
    "X-Api-Key",
    "X-Auth-Token",
)

#: Query parameter and body field names masked by synonym.
#: Compared case-insensitively, ignoring ``-`` and ``_`` so ``api-key``,
#: ``api_key`` and ``APIKEY`` all match.
REDACTED_NAMES: tuple[str, ...] = (
    "access_token",
    "refresh_token",
    "id_token",
    "password",
    "passwd",
    "secret",
    "api_key",
    "token",
)

_REDACTED_HEADERS_LOWER = frozenset(h.lower() for h in REDACTED_HEADERS)


def _normalize(name: str) -> str:
    return name.strip().lower().replace("-", "_")


_REDACTED_NAMES_NORMALIZED = frozenset(_normalize(n) for n in REDACTED_NAMES)


def is_sensitive_header(name: str) -> bool:
    """True when this header name is masked by the default policy."""
    return name.strip().lower() in _REDACTED_HEADERS_LOWER


def is_sensitive_name(name: str) -> bool:
    """True when this query-parameter or body-field name is masked.

    Matching is case-insensitive and treats ``-`` and ``_`` as the same
    character, so ``X-Api-Key``, ``x_api_key`` and ``api-key`` all match.
    """
    return _normalize(name) in _REDACTED_NAMES_NORMALIZED


def is_sensitive(name: str, *, location: Literal["header", "query", "body"] = "body") -> bool:
    """True when ``name`` is masked at ``location``."""
    if location == "header":
        return is_sensitive_header(name)
    return is_sensitive_name(name)


def redaction_policy() -> dict[str, Any]:
    """The default redaction policy, in a form a UI can consume directly."""
    return {
        "success": True,
        "placeholder": REDACTION_PLACEHOLDER,
        "headers": list(REDACTED_HEADERS),
        "names": list(REDACTED_NAMES),
        "match": {
            "headers": "case-insensitive exact name",
            "names": "case-insensitive, '-' and '_' are equivalent",
        },
        "applies_to": ["query", "body"],
        "affects_forwarded_traffic": False,
        "note": (
            "Display and export policy only: the proxy still forwards the real "
            "header, query parameter and body values."
        ),
    }
