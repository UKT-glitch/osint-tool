"""Command-line interface for the OSINT tool.

Usage examples::

    osint-tool username johndoe
    osint-tool email user@example.com --hibp-key YOUR_KEY
    osint-tool ip 8.8.8.8 --output json
    osint-tool domain github.com --output html --outfile report.html
    osint-tool phone +15555551234
    osint-tool auto johndoe@example.com 8.8.8.8 +15555551234
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.logging import RichHandler

from osint_tool.engine import OsintEngine
from osint_tool.modules import MODULE_REGISTRY
from osint_tool.output import get_formatter

console = Console()


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(console=Console(stderr=True), show_path=False, show_time=False)],
    )


# ---------------------------------------------------------------------------
# Shared options
# ---------------------------------------------------------------------------

_shared_options = [
    click.option("--output", "-o", "output_format",
                 type=click.Choice(["console", "json", "csv", "html"], case_sensitive=False),
                 default="console", show_default=True, help="Output format."),
    click.option("--outfile", "-f", type=click.Path(dir_okay=False, writable=True),
                 default=None, help="Write output to this file instead of stdout."),
    click.option("--timeout", "-t", type=int, default=10, show_default=True,
                 help="HTTP request timeout in seconds."),
    click.option("--proxy", "-p", type=str, default=None,
                 help="Proxy URL (e.g. socks5://127.0.0.1:9050)."),
    click.option("--verbose", "-v", is_flag=True, default=False,
                 help="Enable debug logging."),
]


def shared_options(func: click.decorators.FC) -> click.decorators.FC:
    for option in reversed(_shared_options):
        func = option(func)
    return func


def _write_output(text: str, outfile: str | None) -> None:
    if outfile:
        Path(outfile).write_text(text, encoding="utf-8")
        console.print(f"[green]✓[/green] Report saved to [bold]{outfile}[/bold]")
    else:
        click.echo(text)


def _build_engine(
    timeout: int,
    proxy: str | None,
    extra_module_kwargs: dict[str, dict] | None = None,
) -> OsintEngine:
    proxies = {"http": proxy, "https": proxy} if proxy else None
    return OsintEngine(
        timeout=timeout,
        proxies=proxies,
        module_kwargs=extra_module_kwargs or {},
    )


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------

@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(package_name="osint-tool")
def main() -> None:
    """🔍 OSINT Tool – Enterprise-grade Open Source Intelligence framework.

    \b
    Modules available:
      username  – Check a username across 50+ platforms
      email     – Analyse an email address (MX, SMTP, breaches, Gravatar)
      ip        – Investigate an IP address (geo, reverse-DNS, Shodan)
      domain    – Investigate a domain (WHOIS, DNS, crt.sh subdomains)
      phone     – Parse and analyse a phone number
      auto      – Automatically detect target type and run appropriate modules
    """


# ---------------------------------------------------------------------------
# username
# ---------------------------------------------------------------------------

@main.command()
@click.argument("username")
@click.option("--workers", "-w", type=int, default=20, show_default=True,
              help="Maximum concurrent HTTP workers.")
@shared_options
def username(
    username: str,
    workers: int,
    output_format: str,
    outfile: str | None,
    timeout: int,
    proxy: str | None,
    verbose: bool,
) -> None:
    """Search USERNAME across 50+ social/developer platforms."""
    _setup_logging(verbose)
    engine = _build_engine(timeout, proxy, {"username": {"max_workers": workers}})
    results = engine.run(targets=[username], modules=["username"])
    formatter = get_formatter(output_format)
    _write_output(formatter.format(results), outfile)


# ---------------------------------------------------------------------------
# email
# ---------------------------------------------------------------------------

@main.command()
@click.argument("address")
@click.option("--hibp-key", envvar="HIBP_API_KEY", default=None,
              help="HaveIBeenPwned API key (or set HIBP_API_KEY env var).")
@shared_options
def email(
    address: str,
    hibp_key: str | None,
    output_format: str,
    outfile: str | None,
    timeout: int,
    proxy: str | None,
    verbose: bool,
) -> None:
    """Analyse email ADDRESS (MX, SMTP, Gravatar, HIBP breach check)."""
    _setup_logging(verbose)
    engine = _build_engine(timeout, proxy, {"email": {"hibp_api_key": hibp_key}})
    results = engine.run(targets=[address], modules=["email"])
    formatter = get_formatter(output_format)
    _write_output(formatter.format(results), outfile)


# ---------------------------------------------------------------------------
# ip
# ---------------------------------------------------------------------------

@main.command()
@click.argument("address")
@shared_options
def ip(
    address: str,
    output_format: str,
    outfile: str | None,
    timeout: int,
    proxy: str | None,
    verbose: bool,
) -> None:
    """Investigate IP ADDRESS (geolocation, reverse-DNS, Shodan InternetDB)."""
    _setup_logging(verbose)
    engine = _build_engine(timeout, proxy)
    results = engine.run(targets=[address], modules=["ip_domain"])
    formatter = get_formatter(output_format)
    _write_output(formatter.format(results), outfile)


# ---------------------------------------------------------------------------
# domain
# ---------------------------------------------------------------------------

@main.command()
@click.argument("name")
@shared_options
def domain(
    name: str,
    output_format: str,
    outfile: str | None,
    timeout: int,
    proxy: str | None,
    verbose: bool,
) -> None:
    """Investigate domain NAME (WHOIS, DNS records, crt.sh subdomains)."""
    _setup_logging(verbose)
    engine = _build_engine(timeout, proxy)
    results = engine.run(targets=[name], modules=["ip_domain"])
    formatter = get_formatter(output_format)
    _write_output(formatter.format(results), outfile)


# ---------------------------------------------------------------------------
# phone
# ---------------------------------------------------------------------------

@main.command()
@click.argument("number")
@shared_options
def phone(
    number: str,
    output_format: str,
    outfile: str | None,
    timeout: int,
    proxy: str | None,
    verbose: bool,
) -> None:
    """Parse and analyse phone NUMBER (validation, carrier, geolocation)."""
    _setup_logging(verbose)
    engine = _build_engine(timeout, proxy)
    results = engine.run(targets=[number], modules=["phone"])
    formatter = get_formatter(output_format)
    _write_output(formatter.format(results), outfile)


# ---------------------------------------------------------------------------
# auto
# ---------------------------------------------------------------------------

@main.command()
@click.argument("targets", nargs=-1, required=True)
@click.option("--hibp-key", envvar="HIBP_API_KEY", default=None,
              help="HaveIBeenPwned API key for email breach lookups.")
@shared_options
def auto(
    targets: tuple[str, ...],
    hibp_key: str | None,
    output_format: str,
    outfile: str | None,
    timeout: int,
    proxy: str | None,
    verbose: bool,
) -> None:
    """Auto-detect type for each TARGET and run appropriate module(s)."""
    _setup_logging(verbose)
    engine = _build_engine(timeout, proxy, {"email": {"hibp_api_key": hibp_key}})
    results = engine.run(targets=list(targets))
    formatter = get_formatter(output_format)
    _write_output(formatter.format(results), outfile)


# ---------------------------------------------------------------------------
# list-modules
# ---------------------------------------------------------------------------

@main.command("list-modules")
def list_modules() -> None:
    """List all available OSINT modules."""
    from rich.table import Table

    table = Table(title="Available OSINT Modules", show_lines=True)
    table.add_column("Name", style="bold cyan")
    table.add_column("Description")
    table.add_column("Target types", style="dim")

    for name, cls in MODULE_REGISTRY.items():
        table.add_row(name, cls.description, ", ".join(cls.supported_target_types))

    console.print(table)


if __name__ == "__main__":
    main()
