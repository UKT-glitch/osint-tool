"""Tests for validation utilities."""

from __future__ import annotations

import pytest

from osint_tool.utils.validators import (
    detect_target_type,
    is_domain,
    is_email,
    is_ipv4,
    is_phone,
)


class TestIsEmail:
    def test_valid(self) -> None:
        assert is_email("user@example.com")
        assert is_email("alice.bob+tag@subdomain.domain.io")

    def test_invalid(self) -> None:
        assert not is_email("notanemail")
        assert not is_email("@example.com")
        assert not is_email("user@")


class TestIsIpv4:
    def test_valid(self) -> None:
        assert is_ipv4("8.8.8.8")
        assert is_ipv4("192.168.0.1")
        assert is_ipv4("0.0.0.0")
        assert is_ipv4("255.255.255.255")

    def test_invalid(self) -> None:
        assert not is_ipv4("256.0.0.1")
        assert not is_ipv4("8.8.8")
        assert not is_ipv4("example.com")


class TestIsDomain:
    def test_valid(self) -> None:
        assert is_domain("example.com")
        assert is_domain("sub.example.co.uk")

    def test_invalid(self) -> None:
        assert not is_domain("localhost")
        assert not is_domain("8.8.8.8")


class TestIsPhone:
    def test_valid(self) -> None:
        assert is_phone("+15555551234")
        assert is_phone("15555551234")

    def test_invalid(self) -> None:
        assert not is_phone("abc")
        assert not is_phone("123")  # too short


class TestDetectTargetType:
    @pytest.mark.parametrize("value,expected", [
        ("user@example.com", "email"),
        ("8.8.8.8", "ip"),
        ("github.com", "domain"),
        ("johndoe", "username"),
    ])
    def test_detection(self, value: str, expected: str) -> None:
        assert detect_target_type(value) == expected
