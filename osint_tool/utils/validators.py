"""Validation helpers for common OSINT target types."""

from __future__ import annotations

import re


_EMAIL_RE = re.compile(
    r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
)
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def is_email(value: str) -> bool:
    return bool(_EMAIL_RE.match(value.strip()))


def is_ipv4(value: str) -> bool:
    return bool(_IPV4_RE.match(value.strip()))


def is_domain(value: str) -> bool:
    return bool(_DOMAIN_RE.match(value.strip()))


def is_phone(value: str) -> bool:
    """Return True for strings that look like international phone numbers."""
    stripped = re.sub(r"[\s\-().+]", "", value)
    return stripped.isdigit() and 7 <= len(stripped) <= 15


def detect_target_type(value: str) -> str:
    """Return a best-guess target type string for *value*."""
    if is_email(value):
        return "email"
    if is_ipv4(value):
        return "ip"
    if is_domain(value):
        return "domain"
    if is_phone(value):
        return "phone"
    return "username"
