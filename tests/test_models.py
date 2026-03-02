"""Tests for shared data models."""

from __future__ import annotations

import datetime

import pytest

from osint_tool.models import Finding, FindingLevel, OsintResult


class TestFinding:
    def test_defaults(self) -> None:
        f = Finding(module="test", title="T", description="D")
        assert f.level == FindingLevel.INFO
        assert isinstance(f.timestamp, datetime.datetime)
        assert f.timestamp.tzinfo is not None  # timezone-aware

    def test_to_dict_keys(self) -> None:
        f = Finding(module="m", title="t", description="d", level=FindingLevel.HIGH)
        d = f.to_dict()
        assert d["module"] == "m"
        assert d["level"] == "high"
        assert "timestamp" in d


class TestOsintResult:
    def test_add_finding(self) -> None:
        result = OsintResult(target="target", module="mod")
        result.add_finding("Title", "Desc", FindingLevel.MEDIUM, {"key": "val"})
        assert len(result.findings) == 1
        f = result.findings[0]
        assert f.title == "Title"
        assert f.level == FindingLevel.MEDIUM
        assert f.data == {"key": "val"}

    def test_to_dict_structure(self) -> None:
        result = OsintResult(target="t", module="m")
        result.add_finding("F1", "D1")
        d = result.to_dict()
        assert d["target"] == "t"
        assert d["module"] == "m"
        assert len(d["findings"]) == 1
        assert d["errors"] == []
