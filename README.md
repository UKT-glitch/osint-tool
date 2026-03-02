# 🔍 OSINT Tool

[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An **enterprise-grade Open Source Intelligence (OSINT) framework** built for security professionals, red teams, and investigators.

---

## Features

| Module | Target type | What it does |
|--------|-------------|--------------|
| `username` | username | Checks 50+ social / developer platforms concurrently |
| `email` | email | MX validation, SMTP probe, Gravatar profile, HIBP breach & paste lookup |
| `ip_domain` | IP / domain | Geolocation, reverse-DNS, Shodan InternetDB, WHOIS, DNS enum, crt.sh subdomains |
| `phone` | phone | E.164 parsing, number type, carrier, geolocation, time zones |

**Output formats:** rich terminal, JSON, CSV, self-contained HTML report

---

## Installation

```bash
pip install osint-tool
```

Or for development:

```bash
git clone https://github.com/UKT-glitch/osint-tool.git
cd osint-tool
pip install -e ".[dev]"
```

---

## Quick Start

```bash
# Check a username across 50+ platforms
osint-tool username johndoe

# Investigate an email address
osint-tool email user@example.com

# Investigate an email with breach lookup (requires HaveIBeenPwned API key)
osint-tool email user@example.com --hibp-key YOUR_KEY

# Investigate an IP address
osint-tool ip 8.8.8.8

# Investigate a domain
osint-tool domain github.com

# Parse a phone number
osint-tool phone +15555551234

# Auto-detect target type(s) and run all applicable modules
osint-tool auto johndoe@example.com 8.8.8.8 +15555551234

# Export as JSON
osint-tool domain github.com --output json

# Export as a self-contained HTML report
osint-tool domain github.com --output html --outfile report.html

# List all available modules
osint-tool list-modules
```

---

## Python API

```python
from osint_tool import OsintEngine

# Basic usage – auto-detects target type
engine = OsintEngine()
results = engine.run(targets=["johndoe@example.com"])

for result in results:
    print(f"\n=== {result.target} / {result.module} ===")
    for finding in result.findings:
        print(f"[{finding.level.value}] {finding.title}")
        print(finding.description)

# With HIBP breach check
engine = OsintEngine(
    module_kwargs={"email": {"hibp_api_key": "YOUR_KEY"}},
    timeout=15,
)

# Via Tor proxy
engine = OsintEngine(proxies={"https": "socks5://127.0.0.1:9050"})
```

---

## Common Options

| Flag | Description |
|------|-------------|
| `--output` / `-o` | Output format: `console` (default), `json`, `csv`, `html` |
| `--outfile` / `-f` | Write output to file |
| `--timeout` / `-t` | HTTP timeout in seconds (default: 10) |
| `--proxy` / `-p` | Proxy URL, e.g. `socks5://127.0.0.1:9050` |
| `--verbose` / `-v` | Enable debug logging |
| `--hibp-key` | HaveIBeenPwned API key (also reads `HIBP_API_KEY` env var) |

---

## Architecture

```
osint_tool/
├── __init__.py         # Public API surface
├── cli.py              # Click-based CLI
├── engine.py           # Orchestration layer
├── models.py           # OsintResult, Finding, FindingLevel
├── modules/
│   ├── base.py         # Abstract BaseModule
│   ├── username.py     # Username enumeration
│   ├── email_osint.py  # Email intelligence
│   ├── ip_domain.py    # IP / domain intelligence
│   └── phone.py        # Phone number analysis
├── output/
│   └── formatters.py   # JSON, CSV, HTML, Console formatters
└── utils/
    ├── http.py          # Session factory, retry, rate-limiter
    └── validators.py    # Target-type detection helpers
```

---

## Development

```bash
# Run tests
pytest

# Run tests with coverage
pytest --cov=osint_tool --cov-report=term-missing

# Lint
ruff check .

# Type-check
mypy osint_tool/
```

---

## Legal Notice

This tool is intended for **authorized** security research and investigations only. Always obtain proper authorization before investigating any target. The authors are not responsible for misuse.

---

## License

[MIT](LICENSE) © 2026 UKT-glitch
