"""Tests for CLI commands using Click's test runner."""

from __future__ import annotations

from click.testing import CliRunner

from osint_tool.cli import main


class TestCli:
    def test_main_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "OSINT" in result.output

    def test_list_modules(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["list-modules"])
        assert result.exit_code == 0
        assert "username" in result.output
        assert "email" in result.output

    def test_phone_command(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["phone", "+12025551234"])
        assert result.exit_code == 0
        # Should contain at least geolocation data
        assert "US" in result.output or "Phone" in result.output

    def test_phone_command_json_output(self) -> None:
        import json as json_mod

        runner = CliRunner()
        result = runner.invoke(main, ["phone", "+12025551234", "--output", "json"])
        assert result.exit_code == 0
        data = json_mod.loads(result.output)
        assert isinstance(data, list)
        assert data[0]["module"] == "phone"
