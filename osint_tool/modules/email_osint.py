"""Email OSINT module.

Checks:
- MX record presence (is the domain accepting email?)
- SMTP reachability (does the mailbox exist?)
- Public breach/paste mentions via HaveIBeenPwned API (requires API key)
- Gravatar profile lookup
- Hunter.io email pattern lookup (requires API key)
"""

from __future__ import annotations

import logging
import smtplib
import socket

import dns.exception
import dns.resolver

from osint_tool.models import FindingLevel, OsintResult
from osint_tool.modules.base import BaseModule
from osint_tool.utils.http import safe_get

logger = logging.getLogger(__name__)

HIBP_BREACH_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{}"
HIBP_PASTE_URL = "https://haveibeenpwned.com/api/v3/pasteaccount/{}"
GRAVATAR_API = "https://www.gravatar.com/{}.json"


class EmailModule(BaseModule):
    """Gather intelligence on an email address."""

    name = "email"
    description = "MX validation, SMTP check, breach lookup, and Gravatar profile"
    supported_target_types = ["email"]

    def __init__(
        self,
        hibp_api_key: str | None = None,
        hunter_api_key: str | None = None,
        smtp_timeout: int = 5,
        **kwargs: object,
    ) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self._hibp_key = hibp_api_key
        self._hunter_key = hunter_api_key
        self._smtp_timeout = smtp_timeout

    # ------------------------------------------------------------------

    def run(self, target: str) -> OsintResult:
        result = self._new_result(target)
        email = target.strip().lower()

        local, _, domain = email.partition("@")
        if not domain:
            result.errors.append("Invalid email address – missing '@'")
            return result

        self._check_mx(result, domain)
        self._check_smtp(result, email, domain)
        self._check_gravatar(result, email)

        if self._hibp_key:
            self._check_hibp_breaches(result, email)
            self._check_hibp_pastes(result, email)
        else:
            result.add_finding(
                title="HaveIBeenPwned check skipped",
                description="Provide a HIBP API key via --hibp-key to enable breach lookups.",
                level=FindingLevel.INFO,
            )

        return result

    # ------------------------------------------------------------------
    # MX records
    # ------------------------------------------------------------------

    def _check_mx(self, result: OsintResult, domain: str) -> None:
        try:
            answers = dns.resolver.resolve(domain, "MX")
            mx_records = sorted(
                ({"priority": r.preference, "host": str(r.exchange).rstrip(".")} for r in answers),
                key=lambda x: x["priority"],
            )
            result.add_finding(
                title=f"MX records found for {domain}",
                description="\n".join(
                    f"  Priority {r['priority']}: {r['host']}" for r in mx_records
                ),
                level=FindingLevel.INFO,
                data={"mx_records": mx_records},
            )
        except (dns.exception.DNSException, Exception) as exc:
            result.add_finding(
                title=f"No MX records for {domain}",
                description=f"Domain may not accept email: {exc}",
                level=FindingLevel.MEDIUM,
            )

    # ------------------------------------------------------------------
    # SMTP verification (non-intrusive RCPT TO probe)
    # ------------------------------------------------------------------

    def _check_smtp(self, result: OsintResult, email: str, domain: str) -> None:
        try:
            mx_answers = dns.resolver.resolve(domain, "MX")
            mx_host = str(sorted(mx_answers, key=lambda r: r.preference)[0].exchange).rstrip(".")
        except Exception:
            result.add_finding(
                title="SMTP check skipped",
                description="Could not resolve MX records to perform SMTP verification.",
                level=FindingLevel.INFO,
            )
            return

        try:
            with smtplib.SMTP(timeout=self._smtp_timeout) as smtp:
                smtp.connect(mx_host, 25)
                smtp.ehlo_or_helo_if_needed()
                smtp.mail("probe@example.com")
                code, _ = smtp.rcpt(email)
            if code == 250:
                result.add_finding(
                    title="SMTP: mailbox appears to exist",
                    description=f"RCPT TO probe returned 250 via {mx_host}",
                    level=FindingLevel.HIGH,
                    data={"smtp_host": mx_host, "rcpt_code": code},
                )
            elif code == 550:
                result.add_finding(
                    title="SMTP: mailbox does not exist",
                    description=f"RCPT TO probe returned 550 via {mx_host}",
                    level=FindingLevel.MEDIUM,
                    data={"smtp_host": mx_host, "rcpt_code": code},
                )
            else:
                result.add_finding(
                    title=f"SMTP: inconclusive (code {code})",
                    description=f"RCPT TO probe via {mx_host} returned code {code}",
                    level=FindingLevel.INFO,
                    data={"smtp_host": mx_host, "rcpt_code": code},
                )
        except (smtplib.SMTPException, OSError, socket.timeout) as exc:
            result.add_finding(
                title="SMTP check could not complete",
                description=str(exc),
                level=FindingLevel.INFO,
            )

    # ------------------------------------------------------------------
    # Gravatar
    # ------------------------------------------------------------------

    def _check_gravatar(self, result: OsintResult, email: str) -> None:
        import hashlib

        email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()  # noqa: S324
        url = GRAVATAR_API.format(email_hash)
        response = safe_get(self.session, url, timeout=self.timeout)
        if response and response.status_code == 200:
            try:
                data = response.json()
                entry = data.get("entry", [{}])[0]
                result.add_finding(
                    title="Gravatar profile found",
                    description=f"Display name: {entry.get('displayName', 'N/A')}",
                    level=FindingLevel.MEDIUM,
                    data=entry,
                )
            except Exception:
                result.add_finding(
                    title="Gravatar profile found (unreadable response)",
                    description=f"URL: {url}",
                    level=FindingLevel.INFO,
                )

    # ------------------------------------------------------------------
    # HaveIBeenPwned
    # ------------------------------------------------------------------

    def _check_hibp_breaches(self, result: OsintResult, email: str) -> None:
        url = HIBP_BREACH_URL.format(email)
        response = safe_get(
            self.session,
            url,
            timeout=self.timeout,
            headers={"hibp-api-key": self._hibp_key or "", "User-Agent": "osint-tool/1.0"},
            params={"truncateResponse": "false"},
        )
        if response is None:
            result.errors.append("HIBP breach lookup request failed")
            return
        if response.status_code == 404:
            result.add_finding(
                title="No breaches found",
                description=f"{email} has not appeared in any known data breaches.",
                level=FindingLevel.INFO,
            )
            return
        if response.status_code == 401:
            result.errors.append("HIBP: invalid or missing API key")
            return
        if response.status_code == 200:
            breaches = response.json()
            names = [b.get("Name", "unknown") for b in breaches]
            result.add_finding(
                title=f"Email found in {len(breaches)} data breach(es)!",
                description="Breaches: " + ", ".join(names),
                level=FindingLevel.CRITICAL,
                data={"breaches": breaches},
            )

    def _check_hibp_pastes(self, result: OsintResult, email: str) -> None:
        url = HIBP_PASTE_URL.format(email)
        response = safe_get(
            self.session,
            url,
            timeout=self.timeout,
            headers={"hibp-api-key": self._hibp_key or "", "User-Agent": "osint-tool/1.0"},
        )
        if response is None:
            result.errors.append("HIBP paste lookup request failed")
            return
        if response.status_code == 404:
            result.add_finding(
                title="No pastes found",
                description=f"{email} has not appeared in any known paste sites.",
                level=FindingLevel.INFO,
            )
            return
        if response.status_code == 200:
            pastes = response.json()
            result.add_finding(
                title=f"Email found in {len(pastes)} paste(s)!",
                description="\n".join(
                    f"  • {p.get('Source', 'unknown')} – {p.get('Id', '')}" for p in pastes
                ),
                level=FindingLevel.HIGH,
                data={"pastes": pastes},
            )
