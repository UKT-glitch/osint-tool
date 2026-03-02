"""Tests for the phone OSINT module."""

from __future__ import annotations

import pytest

from osint_tool.models import FindingLevel
from osint_tool.modules.phone import PhoneModule


class TestPhoneModule:
    def test_valid_us_number(self) -> None:
        module = PhoneModule()
        result = module.run("+12025551234")
        assert result.module == "phone"
        assert len(result.findings) >= 1
        f = result.findings[0]
        assert "US" in f.data.get("region", "")

    def test_invalid_number(self) -> None:
        module = PhoneModule()
        result = module.run("notaphone")
        assert len(result.errors) >= 1 or any(
            f.level == FindingLevel.MEDIUM for f in result.findings
        )

    def test_e164_format_in_data(self) -> None:
        module = PhoneModule()
        result = module.run("+442071838750")  # UK number
        assert result.findings
        data = result.findings[0].data
        assert data.get("e164", "").startswith("+44")
