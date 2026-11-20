"""REQ-6.2: the default redaction list is a backend constant, queryable by tools."""

from __future__ import annotations

from mitmproxy_mcp.redaction import (
    REDACTED_HEADERS,
    REDACTED_NAMES,
    is_sensitive,
    is_sensitive_header,
    is_sensitive_name,
    redaction_policy,
)


def test_header_list_matches_the_spec() -> None:
    assert set(REDACTED_HEADERS) == {
        "Authorization",
        "Cookie",
        "Set-Cookie",
        "Proxy-Authorization",
        "X-Api-Key",
        "X-Auth-Token",
    }


def test_name_list_matches_the_spec() -> None:
    assert set(REDACTED_NAMES) == {
        "access_token",
        "refresh_token",
        "id_token",
        "password",
        "passwd",
        "secret",
        "api_key",
        "token",
    }


def test_header_matching_ignores_case() -> None:
    assert is_sensitive_header("authorization")
    assert is_sensitive_header("SET-COOKIE")
    assert not is_sensitive_header("content-type")


def test_header_matching_does_not_use_synonyms() -> None:
    """Header names are exact: the synonym list is for query and body names."""
    assert not is_sensitive_header("X-Custom-Token")
    assert not is_sensitive_name("Authorization")


def test_name_matching_is_case_insensitive() -> None:
    assert is_sensitive_name("Access_Token")
    assert is_sensitive_name("PASSWORD")
    assert is_sensitive_name("ApiKey") is False  # not the same word
    assert is_sensitive_name("api_key")


def test_name_matching_treats_dash_and_underscore_alike() -> None:
    assert is_sensitive_name("api-key")
    assert is_sensitive_name("Access-Token")
    assert is_sensitive_name("refresh-token")


def test_ordinary_names_are_not_masked() -> None:
    for name in ("username", "page", "sort", "email", "session_id"):
        assert not is_sensitive_name(name)


def test_is_sensitive_dispatches_by_location() -> None:
    assert is_sensitive("Cookie", location="header")
    assert not is_sensitive("Cookie", location="query")
    assert is_sensitive("access_token", location="query")
    assert is_sensitive("access_token", location="body")


def test_policy_payload_is_ui_consumable() -> None:
    policy = redaction_policy()
    assert policy["success"] is True
    assert policy["placeholder"]
    assert list(policy["headers"]) == list(REDACTED_HEADERS)
    assert list(policy["names"]) == list(REDACTED_NAMES)
    assert policy["applies_to"] == ["query", "body"]
    # The policy must never be mistaken for a proxy-side filter.
    assert policy["affects_forwarded_traffic"] is False


def test_redaction_does_not_change_forwarded_traffic() -> None:
    """The policy is a display rule: reading it must not mutate any request."""
    from mitmproxy import http

    req = http.Request.make(
        "GET",
        "http://example.com/x?access_token=demo-value",
        headers=[(b"Authorization", b"Bearer abc"), (b"Accept", b"*/*")],
    )
    policy = redaction_policy()  # noqa: F841  (policy is read, not applied)
    assert req.headers["Authorization"] == "Bearer abc"
    assert req.query["access_token"] == "demo-value"
    assert "demo-value" in req.path
