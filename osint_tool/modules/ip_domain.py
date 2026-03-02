"""IP / Domain OSINT module.

Performs:
- WHOIS lookup (domain registration info)
- DNS record enumeration (A, AAAA, MX, NS, TXT, CNAME, SOA)
- Reverse DNS (PTR) lookup for IP addresses
- IP geolocation via ip-api.com (free, no key required)
- Shodan Internet DB quick check (no key required)
- Subdomain discovery via crt.sh (Certificate Transparency logs)
"""

from __future__ import annotations

import ipaddress
import json
import logging
import socket
from typing import Any

import dns.exception
import dns.resolver
import whois  # python-whois

from osint_tool.models import FindingLevel, OsintResult
from osint_tool.modules.base import BaseModule
from osint_tool.utils.http import safe_get
from osint_tool.utils.validators import is_ipv4

logger = logging.getLogger(__name__)

IP_GEO_URL = "http://ip-api.com/json/{}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,query"
SHODAN_INTERNETDB = "https://internetdb.shodan.io/{}"
CRTSH_URL = "https://crt.sh/?q={}&output=json"

_DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


class IpDomainModule(BaseModule):
    """Enumerate intelligence for an IP address or domain name."""

    name = "ip_domain"
    description = "WHOIS, DNS enumeration, geolocation, Shodan InternetDB, crt.sh subdomains"
    supported_target_types = ["ip", "domain"]

    # ------------------------------------------------------------------

    def run(self, target: str) -> OsintResult:
        result = self._new_result(target)
        target = target.strip()

        if is_ipv4(target):
            self._analyze_ip(result, target)
        else:
            self._analyze_domain(result, target)

        return result

    # ------------------------------------------------------------------
    # IP analysis
    # ------------------------------------------------------------------

    def _analyze_ip(self, result: OsintResult, ip: str) -> None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError as exc:
            result.errors.append(f"Invalid IP address: {exc}")
            return

        # Private / special ranges
        if addr.is_private:
            result.add_finding(
                title="Private IP address",
                description=f"{ip} is a private (RFC-1918) address and will not be publicly routable.",
                level=FindingLevel.INFO,
            )
            return

        self._geolocate_ip(result, ip)
        self._reverse_dns(result, ip)
        self._shodan_internetdb(result, ip)

    def _geolocate_ip(self, result: OsintResult, ip: str) -> None:
        response = safe_get(self.session, IP_GEO_URL.format(ip), timeout=self.timeout)
        if response is None or response.status_code != 200:
            result.errors.append(f"Geolocation lookup failed for {ip}")
            return
        data: dict[str, Any] = response.json()
        if data.get("status") != "success":
            result.errors.append(f"Geolocation API error: {data.get('message')}")
            return

        result.add_finding(
            title=f"IP Geolocation: {ip}",
            description=(
                f"  Country   : {data.get('country')} ({data.get('countryCode')})\n"
                f"  Region    : {data.get('regionName')} ({data.get('region')})\n"
                f"  City      : {data.get('city')}, {data.get('zip')}\n"
                f"  Lat/Lon   : {data.get('lat')}, {data.get('lon')}\n"
                f"  Timezone  : {data.get('timezone')}\n"
                f"  ISP       : {data.get('isp')}\n"
                f"  Org       : {data.get('org')}\n"
                f"  AS        : {data.get('as')} ({data.get('asname')})"
            ),
            level=FindingLevel.INFO,
            data=data,
        )

    def _reverse_dns(self, result: OsintResult, ip: str) -> None:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            result.add_finding(
                title=f"Reverse DNS for {ip}",
                description=f"PTR record resolves to: {hostname}",
                level=FindingLevel.INFO,
                data={"ptr": hostname},
            )
        except socket.herror:
            result.add_finding(
                title=f"No PTR record for {ip}",
                description="Reverse DNS lookup returned no result.",
                level=FindingLevel.INFO,
            )

    def _shodan_internetdb(self, result: OsintResult, ip: str) -> None:
        """Query the Shodan InternetDB (free, no API key) for open ports/CVEs."""
        self._rate_limiter.wait()
        response = safe_get(self.session, SHODAN_INTERNETDB.format(ip), timeout=self.timeout)
        if response is None:
            result.errors.append("Shodan InternetDB request failed")
            return
        if response.status_code == 404:
            result.add_finding(
                title="Shodan: no data for this IP",
                description=f"{ip} was not found in the Shodan InternetDB.",
                level=FindingLevel.INFO,
            )
            return
        if response.status_code != 200:
            return
        data = response.json()
        ports = data.get("ports", [])
        vulns = data.get("vulns", [])
        tags = data.get("tags", [])

        level = FindingLevel.CRITICAL if vulns else (FindingLevel.HIGH if ports else FindingLevel.INFO)
        result.add_finding(
            title=f"Shodan InternetDB: {ip}",
            description=(
                f"  Open ports : {', '.join(str(p) for p in ports) or 'none'}\n"
                f"  Vulns (CVE): {', '.join(vulns) or 'none'}\n"
                f"  Tags       : {', '.join(tags) or 'none'}"
            ),
            level=level,
            data=data,
        )

    # ------------------------------------------------------------------
    # Domain analysis
    # ------------------------------------------------------------------

    def _analyze_domain(self, result: OsintResult, domain: str) -> None:
        self._whois_lookup(result, domain)
        self._dns_enum(result, domain)
        self._crtsh_subdomains(result, domain)

    def _whois_lookup(self, result: OsintResult, domain: str) -> None:
        try:
            w = whois.whois(domain)
            registrar = w.registrar or "N/A"
            creation = str(w.creation_date) if w.creation_date else "N/A"
            expiry = str(w.expiration_date) if w.expiration_date else "N/A"
            updated = str(w.updated_date) if w.updated_date else "N/A"
            name_servers = w.name_servers or []
            if isinstance(name_servers, str):
                name_servers = [name_servers]

            result.add_finding(
                title=f"WHOIS for {domain}",
                description=(
                    f"  Registrar    : {registrar}\n"
                    f"  Created      : {creation}\n"
                    f"  Expires      : {expiry}\n"
                    f"  Updated      : {updated}\n"
                    f"  Name Servers : {', '.join(sorted({ns.lower().rstrip('.') for ns in name_servers if ns}))}"
                ),
                level=FindingLevel.INFO,
                data={
                    "registrar": registrar,
                    "creation_date": creation,
                    "expiration_date": expiry,
                    "updated_date": updated,
                    "name_servers": sorted({ns.lower().rstrip(".") for ns in name_servers if ns}),
                },
            )
        except Exception as exc:
            result.errors.append(f"WHOIS lookup failed: {exc}")

    def _dns_enum(self, result: OsintResult, domain: str) -> None:
        collected: dict[str, list[str]] = {}
        for rtype in _DNS_RECORD_TYPES:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                collected[rtype] = [str(r) for r in answers]
            except (dns.exception.DNSException, Exception):
                pass  # record type not present – skip silently

        if collected:
            lines = []
            for rtype, records in sorted(collected.items()):
                for rec in records:
                    lines.append(f"  {rtype:<6} {rec}")
            result.add_finding(
                title=f"DNS records for {domain}",
                description="\n".join(lines),
                level=FindingLevel.INFO,
                data={"dns_records": collected},
            )

    def _crtsh_subdomains(self, result: OsintResult, domain: str) -> None:
        self._rate_limiter.wait()
        response = safe_get(self.session, CRTSH_URL.format(domain), timeout=self.timeout)
        if response is None or response.status_code != 200:
            result.errors.append(f"crt.sh lookup failed for {domain}")
            return

        try:
            entries = response.json()
        except (json.JSONDecodeError, Exception):
            result.errors.append("crt.sh returned non-JSON response")
            return

        subdomains: set[str] = set()
        for entry in entries:
            names = entry.get("name_value", "")
            for name in names.split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name and name.endswith(domain.lower()):
                    subdomains.add(name)

        if subdomains:
            sorted_subs = sorted(subdomains)
            result.add_finding(
                title=f"crt.sh: {len(sorted_subs)} unique subdomain(s) found for {domain}",
                description="\n".join(f"  • {s}" for s in sorted_subs),
                level=FindingLevel.HIGH if len(sorted_subs) > 5 else FindingLevel.MEDIUM,
                data={"subdomains": sorted_subs},
            )
        else:
            result.add_finding(
                title=f"No subdomains found via crt.sh for {domain}",
                description="Certificate Transparency log search returned no results.",
                level=FindingLevel.INFO,
            )
