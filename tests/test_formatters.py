"""Tests for output formatters."""

from __future__ import annotations

import json

import pytest

from osint_tool.models import FindingLevel, OsintResult
from osint_tool.output import CsvFormatter, HtmlFormatter, JsonFormatter, get_formatter


def _sample_result() -> OsintResult:
    r = OsintResult(target="johndoe", module="username")
    r.add_finding("Found on GitHub", "https://github.com/johndoe", FindingLevel.HIGH)
    r.errors.append("platform X timed out")
    return r


class TestJsonFormatter:
    def test_output_is_valid_json(self) -> None:
        fmt = JsonFormatter()
        output = fmt.format([_sample_result()])
        data = json.loads(output)
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["target"] == "johndoe"
        assert len(data[0]["findings"]) == 1
        assert data[0]["errors"] == ["platform X timed out"]

    def test_empty_results(self) -> None:
        output = JsonFormatter().format([])
        assert json.loads(output) == []


class TestCsvFormatter:
    def test_has_header(self) -> None:
        fmt = CsvFormatter()
        output = fmt.format([_sample_result()])
        lines = output.strip().splitlines()
        assert lines[0].startswith("target,module,level")

    def test_one_row_per_finding(self) -> None:
        r = _sample_result()
        r.add_finding("Another finding", "desc", FindingLevel.INFO)
        output = CsvFormatter().format([r])
        lines = output.strip().splitlines()
        assert len(lines) == 3  # header + 2 findings


class TestHtmlFormatter:
    def test_contains_target(self) -> None:
        output = HtmlFormatter().format([_sample_result()])
        assert "johndoe" in output
        assert "<!DOCTYPE html>" in output

    def test_badge_classes_present(self) -> None:
        output = HtmlFormatter().format([_sample_result()])
        assert "badge-high" in output


class TestGetFormatter:
    def test_known_formatters(self) -> None:
        for name in ("json", "csv", "html", "console"):
            fmt = get_formatter(name)
            assert fmt is not None

    def test_unknown_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown formatter"):
            get_formatter("xml")
