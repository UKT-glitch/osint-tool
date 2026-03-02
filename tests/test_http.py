"""Tests for HTTP utilities."""

from __future__ import annotations

import time

import responses as resp_lib

from osint_tool.utils.http import RateLimiter, build_session, safe_get


def test_build_session_returns_session() -> None:
    session = build_session()
    assert session is not None
    assert "User-Agent" in session.headers


def test_build_session_custom_headers() -> None:
    session = build_session(headers={"X-Custom": "test"})
    assert session.headers["X-Custom"] == "test"


class TestRateLimiter:
    def test_no_wait_on_first_call(self) -> None:
        rl = RateLimiter(calls_per_second=100)
        t0 = time.monotonic()
        rl.wait()
        elapsed = time.monotonic() - t0
        assert elapsed < 0.1  # essentially instant

    def test_enforces_interval(self) -> None:
        rl = RateLimiter(calls_per_second=5)
        rl.wait()  # prime
        t0 = time.monotonic()
        rl.wait()  # should block ~0.2 s
        elapsed = time.monotonic() - t0
        assert elapsed >= 0.15  # allow slight scheduling jitter


@resp_lib.activate
def test_safe_get_success() -> None:
    resp_lib.add(resp_lib.GET, "https://example.com", body="ok", status=200)
    session = build_session()
    response = safe_get(session, "https://example.com")
    assert response is not None
    assert response.status_code == 200


@resp_lib.activate
def test_safe_get_returns_none_on_connection_error() -> None:
    import requests

    resp_lib.add(resp_lib.GET, "https://example.com", body=requests.ConnectionError("fail"))
    session = build_session()
    response = safe_get(session, "https://example.com")
    assert response is None
