"""Phone number OSINT module.

Uses the `phonenumbers` library (libphonenumber port) to:
- Parse and validate the number
- Extract carrier and time zone information
- Enumerate the number type (mobile, fixed-line, VoIP, etc.)

No external API calls are required for basic analysis.
"""

from __future__ import annotations

import logging

import phonenumbers
from phonenumbers import (
    NumberParseException,
    PhoneNumberFormat,
    PhoneNumberType,
    carrier,
    geocoder,
    timezone,
)

from osint_tool.models import FindingLevel, OsintResult
from osint_tool.modules.base import BaseModule

logger = logging.getLogger(__name__)

_TYPE_LABELS: dict[PhoneNumberType, str] = {
    PhoneNumberType.MOBILE: "Mobile",
    PhoneNumberType.FIXED_LINE: "Fixed-line",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed-line or Mobile",
    PhoneNumberType.TOLL_FREE: "Toll-free",
    PhoneNumberType.PREMIUM_RATE: "Premium-rate",
    PhoneNumberType.SHARED_COST: "Shared-cost",
    PhoneNumberType.VOIP: "VoIP",
    PhoneNumberType.PERSONAL_NUMBER: "Personal number",
    PhoneNumberType.PAGER: "Pager",
    PhoneNumberType.UAN: "UAN",
    PhoneNumberType.UNKNOWN: "Unknown",
}


class PhoneModule(BaseModule):
    """Parse and analyse a phone number using libphonenumber."""

    name = "phone"
    description = "Parse, validate, and geolocate a phone number"
    supported_target_types = ["phone"]

    def run(self, target: str) -> OsintResult:
        result = self._new_result(target)
        raw = target.strip()

        # Attempt to parse with a leading '+' if not present
        candidates = [raw, f"+{raw.lstrip('+')}"]
        parsed = None
        for candidate in candidates:
            try:
                parsed = phonenumbers.parse(candidate, None)
                break
            except NumberParseException:
                continue

        if parsed is None:
            result.errors.append(
                f"Could not parse '{raw}' as a phone number. "
                "Ensure it is in E.164 format, e.g. +15555551234."
            )
            return result

        if not phonenumbers.is_valid_number(parsed):
            result.add_finding(
                title="Invalid phone number",
                description=f"'{raw}' parsed but failed libphonenumber validity check.",
                level=FindingLevel.MEDIUM,
            )
            return result

        e164 = phonenumbers.format_number(parsed, PhoneNumberFormat.E164)
        intl = phonenumbers.format_number(parsed, PhoneNumberFormat.INTERNATIONAL)
        national = phonenumbers.format_number(parsed, PhoneNumberFormat.NATIONAL)
        number_type = phonenumbers.number_type(parsed)
        carrier_name = carrier.name_for_number(parsed, "en")
        geo = geocoder.description_for_number(parsed, "en")
        timezones = list(timezone.time_zones_for_number(parsed))
        region = phonenumbers.region_code_for_number(parsed)

        result.add_finding(
            title=f"Phone number analysis: {intl}",
            description=(
                f"  E.164 format  : {e164}\n"
                f"  International : {intl}\n"
                f"  National      : {national}\n"
                f"  Region/Country: {region}\n"
                f"  Number type   : {_TYPE_LABELS.get(number_type, 'Unknown')}\n"
                f"  Carrier       : {carrier_name or 'N/A'}\n"
                f"  Location      : {geo or 'N/A'}\n"
                f"  Time zone(s)  : {', '.join(timezones) or 'N/A'}"
            ),
            level=FindingLevel.INFO,
            data={
                "e164": e164,
                "international": intl,
                "national": national,
                "region": region,
                "type": _TYPE_LABELS.get(number_type, "Unknown"),
                "carrier": carrier_name,
                "location": geo,
                "timezones": timezones,
            },
        )

        # Flag premium or suspicious types
        if number_type in (PhoneNumberType.PREMIUM_RATE, PhoneNumberType.SHARED_COST):
            result.add_finding(
                title="Premium-rate or shared-cost number detected",
                description="Calling this number may incur higher-than-normal charges.",
                level=FindingLevel.HIGH,
            )

        return result
