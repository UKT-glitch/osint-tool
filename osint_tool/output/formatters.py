"""Output formatters: JSON, CSV, HTML, and rich console."""

from __future__ import annotations

import csv
import io
import json
import textwrap
from abc import ABC, abstractmethod
from typing import Any

from osint_tool.models import FindingLevel, OsintResult

# Colour mapping for terminal (ANSI / rich)
_LEVEL_COLOR: dict[FindingLevel, str] = {
    FindingLevel.CRITICAL: "bold red",
    FindingLevel.HIGH: "red",
    FindingLevel.MEDIUM: "yellow",
    FindingLevel.LOW: "cyan",
    FindingLevel.INFO: "white",
}


class BaseFormatter(ABC):
    @abstractmethod
    def format(self, results: list[OsintResult]) -> str:
        """Return a string representation of *results*."""


# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------

class JsonFormatter(BaseFormatter):
    """Serialise results as a JSON document."""

    def __init__(self, indent: int = 2) -> None:
        self._indent = indent

    def format(self, results: list[OsintResult]) -> str:
        return json.dumps([r.to_dict() for r in results], indent=self._indent, ensure_ascii=False)


# ---------------------------------------------------------------------------
# CSV formatter
# ---------------------------------------------------------------------------

class CsvFormatter(BaseFormatter):
    """Flat CSV with one row per finding."""

    FIELDS = ["target", "module", "level", "title", "description"]

    def format(self, results: list[OsintResult]) -> str:
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=self.FIELDS, extrasaction="ignore")
        writer.writeheader()
        for result in results:
            for finding in result.findings:
                writer.writerow({
                    "target": result.target,
                    "module": result.module,
                    "level": finding.level.value,
                    "title": finding.title,
                    "description": finding.description.replace("\n", " | "),
                })
        return buf.getvalue()


# ---------------------------------------------------------------------------
# HTML formatter
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>OSINT Report</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:'Segoe UI',Arial,sans-serif;background:#0f1117;color:#e0e0e0;padding:2rem}}
    h1{{color:#7cb9ff;margin-bottom:1.5rem;font-size:1.8rem}}
    .target-block{{border:1px solid #2e3250;border-radius:8px;margin-bottom:2rem;overflow:hidden}}
    .target-header{{background:#1a1d2e;padding:1rem 1.5rem;font-size:1.1rem;font-weight:bold;color:#a0c4ff}}
    .finding{{padding:1rem 1.5rem;border-top:1px solid #1a1d2e}}
    .finding-title{{font-weight:bold;margin-bottom:.4rem}}
    .finding-desc{{font-size:.85rem;color:#aaa;white-space:pre-wrap}}
    .badge{{display:inline-block;padding:.2rem .6rem;border-radius:4px;font-size:.75rem;font-weight:bold;margin-right:.5rem;text-transform:uppercase}}
    .badge-critical{{background:#b91c1c;color:#fff}}
    .badge-high{{background:#c2410c;color:#fff}}
    .badge-medium{{background:#b45309;color:#fff}}
    .badge-low{{background:#0e7490;color:#fff}}
    .badge-info{{background:#374151;color:#ddd}}
    .errors{{background:#1f0000;border-left:4px solid #b91c1c;padding:.7rem 1rem;margin:.5rem 1.5rem;font-size:.8rem;color:#f87171}}
  </style>
</head>
<body>
  <h1>🔍 OSINT Investigation Report</h1>
  {body}
</body>
</html>
"""


class HtmlFormatter(BaseFormatter):
    """Generate a self-contained dark-theme HTML report."""

    def format(self, results: list[OsintResult]) -> str:
        blocks: list[str] = []

        # Group by target
        by_target: dict[str, list[OsintResult]] = {}
        for r in results:
            by_target.setdefault(r.target, []).append(r)

        for target, target_results in by_target.items():
            findings_html: list[str] = []
            for result in target_results:
                for finding in result.findings:
                    badge_cls = f"badge-{finding.level.value}"
                    desc_escaped = self._escape(finding.description)
                    findings_html.append(
                        f'<div class="finding">'
                        f'<div class="finding-title">'
                        f'<span class="badge {badge_cls}">{finding.level.value}</span>'
                        f'{self._escape(finding.title)}'
                        f'</div>'
                        f'<div class="finding-desc">{desc_escaped}</div>'
                        f'</div>'
                    )
                if result.errors:
                    err_html = "<br>".join(self._escape(e) for e in result.errors)
                    findings_html.append(f'<div class="errors">⚠ {err_html}</div>')

            block = (
                f'<div class="target-block">'
                f'<div class="target-header">🎯 {self._escape(target)}</div>'
                + "".join(findings_html)
                + "</div>"
            )
            blocks.append(block)

        return _HTML_TEMPLATE.format(body="\n  ".join(blocks))

    @staticmethod
    def _escape(text: str) -> str:
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )


# ---------------------------------------------------------------------------
# Rich console formatter (plain-text fallback when rich is unavailable)
# ---------------------------------------------------------------------------

class ConsoleFormatter(BaseFormatter):
    """Render findings to the terminal using *rich* when available."""

    def format(self, results: list[OsintResult]) -> str:
        try:
            return self._format_rich(results)
        except ImportError:
            return self._format_plain(results)

    @staticmethod
    def _format_rich(results: list[OsintResult]) -> str:
        from io import StringIO

        from rich.console import Console
        from rich.panel import Panel
        from rich.text import Text

        buf = StringIO()
        console = Console(file=buf, highlight=False, markup=True, width=100)

        for result in results:
            panel_lines: list[str] = []
            for finding in result.findings:
                colour = _LEVEL_COLOR[finding.level]
                panel_lines.append(
                    f"[{colour}][{finding.level.value.upper()}][/{colour}] {finding.title}"
                )
                if finding.description:
                    panel_lines.append(finding.description)
                panel_lines.append("")

            if result.errors:
                for err in result.errors:
                    panel_lines.append(f"[red]ERROR:[/red] {err}")

            console.print(
                Panel(
                    "\n".join(panel_lines).strip(),
                    title=f"[bold cyan]{result.target}[/bold cyan] — [dim]{result.module}[/dim]",
                    border_style="blue",
                )
            )

        return buf.getvalue()

    @staticmethod
    def _format_plain(results: list[OsintResult]) -> str:
        lines: list[str] = []
        for result in results:
            lines.append(f"\n{'='*60}")
            lines.append(f"Target : {result.target}")
            lines.append(f"Module : {result.module}")
            lines.append(f"{'='*60}")
            for finding in result.findings:
                lines.append(f"\n[{finding.level.value.upper()}] {finding.title}")
                if finding.description:
                    for line in finding.description.splitlines():
                        lines.append("  " + line)
            if result.errors:
                for err in result.errors:
                    lines.append(f"  ERROR: {err}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

_FORMATTERS: dict[str, type[BaseFormatter]] = {
    "json": JsonFormatter,
    "csv": CsvFormatter,
    "html": HtmlFormatter,
    "console": ConsoleFormatter,
}


def get_formatter(name: str) -> BaseFormatter:
    """Return an instantiated formatter by name."""
    cls = _FORMATTERS.get(name.lower())
    if cls is None:
        raise ValueError(f"Unknown formatter '{name}'. Choose from: {list(_FORMATTERS)}")
    return cls()
