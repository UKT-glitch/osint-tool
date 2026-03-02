"""Tests for the username OSINT module (mocked HTTP)."""

from __future__ import annotations

import pytest
import responses as resp_lib

from osint_tool.modules.username import PLATFORMS, UsernameModule


@resp_lib.activate
def test_username_found_on_github() -> None:
    """If GitHub returns 200, the username should be flagged as found."""
    # Stub all platform requests to 404 except GitHub
    for platform in PLATFORMS:
        url = platform.url_template.format("testuser")
        status = 200 if platform.name == "GitHub" else 404
        resp_lib.add(resp_lib.GET, url, status=status, body="")

    module = UsernameModule(max_workers=5)
    result = module.run("testuser")
    assert result.module == "username"
    assert result.target == "testuser"
    assert any("found" in f.title.lower() for f in result.findings)
    found_data = next(
        (f.data for f in result.findings if f.data.get("found")), {}
    )
    found_names = [p["platform"] for p in found_data.get("found", [])]
    assert "GitHub" in found_names


@resp_lib.activate
def test_username_not_found_anywhere() -> None:
    """If all platforms return 404, no active profiles should be reported."""
    for platform in PLATFORMS:
        url = platform.url_template.format("xyznonexistent99")
        resp_lib.add(resp_lib.GET, url, status=404, body="")

    module = UsernameModule(max_workers=5)
    result = module.run("xyznonexistent99")
    assert any("not found" in f.title.lower() for f in result.findings)
