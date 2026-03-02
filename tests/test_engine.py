"""Tests for the OSINT engine orchestrator."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from osint_tool.engine import OsintEngine
from osint_tool.models import OsintResult


class TestOsintEngine:
    def test_auto_detects_email_module(self) -> None:
        engine = OsintEngine()
        with patch("osint_tool.modules.email_osint.EmailModule.run") as mock_run:
            mock_run.return_value = OsintResult(target="x@y.com", module="email")
            results = engine.run(targets=["x@y.com"])
        assert any(r.module == "email" for r in results)

    def test_explicit_module_selection(self) -> None:
        engine = OsintEngine()
        with patch("osint_tool.modules.phone.PhoneModule.run") as mock_run:
            mock_run.return_value = OsintResult(target="+15555551234", module="phone")
            results = engine.run(targets=["+15555551234"], modules=["phone"])
        assert any(r.module == "phone" for r in results)

    def test_unknown_module_skipped(self) -> None:
        engine = OsintEngine()
        results = engine.run(targets=["test"], modules=["nonexistent_module"])
        assert results == []

    def test_module_exception_captured_in_errors(self) -> None:
        engine = OsintEngine()
        with patch("osint_tool.modules.phone.PhoneModule.run", side_effect=RuntimeError("boom")):
            results = engine.run(targets=["+15555551234"], modules=["phone"])
        assert results
        assert any("boom" in e for r in results for e in r.errors)
