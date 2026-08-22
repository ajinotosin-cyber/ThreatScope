"""
ioc_analysis.py
----------------
Replaces the old threat_lookup.py + ioc_lookup.py (the latter is removed —
see README "Removed files"). This module:

1. Detects and validates the type of an indicator of compromise (IOC):
   IPv4 address, domain, URL, or file hash (MD5/SHA1/SHA256).
2. Routes each type to only the providers that support it (AbuseIPDB is
   IP-only and is never called with a domain/URL/hash — this was a real bug
   in the previous version, which passed arbitrary search text into
   IP-shaped API calls).
3. Aggregates provider results into a single structured InvestigationResult
   with an explicit status, so a provider failure is never silently
   reported as "Safe" / "0 risk".
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Optional

import api_client
from api_client import (
    STATUS_OK, STATUS_NOT_CONFIGURED, STATUS_INVALID_KEY, STATUS_RATE_LIMITED,
    STATUS_NOT_FOUND, STATUS_PROVIDER_ERROR, STATUS_NETWORK_ERROR,
)
from config import ProviderConfig
import mitre_mapper

IOC_TYPE_IPV4 = "IPv4"
IOC_TYPE_DOMAIN = "Domain"
IOC_TYPE_URL = "URL"
IOC_TYPE_HASH_MD5 = "MD5 Hash"
IOC_TYPE_HASH_SHA1 = "SHA1 Hash"
IOC_TYPE_HASH_SHA256 = "SHA256 Hash"
IOC_TYPE_INVALID = "Invalid"

# Overall investigation status shown to the user — distinct from the
# per-provider ProviderResult status.
RESULT_VALID = "VALID RESULT"
RESULT_NO_DATA = "NO DATA FOUND"
RESULT_INVALID_IOC = "INVALID IOC"
RESULT_PROVIDERS_UNAVAILABLE = "PROVIDERS UNAVAILABLE"

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
_MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1_RE = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


def detect_ioc_type(value: str) -> str:
    """Best-effort, conservative IOC type detection. Returns IOC_TYPE_INVALID
    if the value doesn't clearly match a supported shape — callers must not
    guess further than this."""
    value = (value or "").strip()
    if not value:
        return IOC_TYPE_INVALID

    if value.startswith("http://") or value.startswith("https://"):
        return IOC_TYPE_URL

    try:
        ipaddress.IPv4Address(value)
        return IOC_TYPE_IPV4
    except ValueError:
        pass

    # A value shaped like a dotted-quad (four all-numeric, dot-separated
    # labels) but rejected by IPv4Address (e.g. octet > 255) is an invalid
    # IP, not a domain — real domains never have an all-numeric final label
    # (ICANN disallows all-numeric TLDs), so don't let this fall through to
    # the domain check below.
    if re.match(r"^\d+(\.\d+){3}$", value):
        return IOC_TYPE_INVALID

    if _SHA256_RE.match(value):
        return IOC_TYPE_HASH_SHA256
    if _SHA1_RE.match(value):
        return IOC_TYPE_HASH_SHA1
    if _MD5_RE.match(value):
        return IOC_TYPE_HASH_MD5

    if _DOMAIN_RE.match(value):
        return IOC_TYPE_DOMAIN

    return IOC_TYPE_INVALID


@dataclass
class InvestigationResult:
    ioc_value: str
    ioc_type: str
    result_status: str
    classification: str = "Unknown"
    severity: str = "Unknown"
    confidence: str = "Low"
    explanation: str = ""
    country: Optional[str] = None
    abuse_score: Optional[int] = None
    vt_malicious_count: Optional[int] = None
    provider_statuses: dict = field(default_factory=dict)   # provider name -> status
    provider_messages: dict = field(default_factory=dict)   # provider name -> human message
    mitre: list = field(default_factory=list)                # list of mitre_mapper.MitreTechnique


def _vt_malicious_count(vt_result: api_client.ProviderResult, ioc_type: str) -> Optional[int]:
    if not vt_result.ok or not vt_result.data:
        return None
    try:
        attrs = vt_result.data["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        return int(stats.get("malicious", 0))
    except (KeyError, TypeError, ValueError):
        return None


def _vt_country(vt_result: api_client.ProviderResult) -> Optional[str]:
    if not vt_result.ok or not vt_result.data:
        return None
    try:
        return vt_result.data["data"]["attributes"].get("country")
    except (KeyError, TypeError):
        return None


def investigate(ioc_value: str, providers: ProviderConfig) -> InvestigationResult:
    ioc_value = (ioc_value or "").strip()
    ioc_type = detect_ioc_type(ioc_value)

    if ioc_type == IOC_TYPE_INVALID:
        return InvestigationResult(
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            result_status=RESULT_INVALID_IOC,
            explanation=(
                "This value doesn't match a supported IOC format "
                "(IPv4 address, domain, http(s) URL, or MD5/SHA1/SHA256 hash)."
            ),
        )

    result = InvestigationResult(ioc_value=ioc_value, ioc_type=ioc_type, result_status=RESULT_NO_DATA)

    vt_result: Optional[api_client.ProviderResult] = None
    abuse_result: Optional[api_client.ProviderResult] = None
    otx_result: Optional[api_client.ProviderResult] = None

    if ioc_type == IOC_TYPE_IPV4:
        vt_result = api_client.virustotal_ip(ioc_value, providers.virustotal_key)
        abuse_result = api_client.abuseipdb_check(ioc_value, providers.abuseipdb_key)
        otx_result = api_client.otx_ip(ioc_value, providers.otx_key)
    elif ioc_type == IOC_TYPE_DOMAIN:
        vt_result = api_client.virustotal_domain(ioc_value, providers.virustotal_key)
        otx_result = api_client.otx_domain(ioc_value, providers.otx_key)
        # AbuseIPDB is IP-only by design — intentionally not called here.
    elif ioc_type == IOC_TYPE_URL:
        vt_result = api_client.virustotal_url(ioc_value, providers.virustotal_key)
        # AbuseIPDB/OTX have no general-purpose URL endpoint used here.
    elif ioc_type in (IOC_TYPE_HASH_MD5, IOC_TYPE_HASH_SHA1, IOC_TYPE_HASH_SHA256):
        vt_result = api_client.virustotal_file_hash(ioc_value, providers.virustotal_key)
        # AbuseIPDB/OTX don't support hash lookups in this integration.

    provider_results = [r for r in (vt_result, abuse_result, otx_result) if r is not None]
    for r in provider_results:
        result.provider_statuses[r.provider] = r.status
        result.provider_messages[r.provider] = r.message

    if vt_result:
        result.vt_malicious_count = _vt_malicious_count(vt_result, ioc_type)
        country = _vt_country(vt_result)
        if country:
            result.country = country

    if abuse_result and abuse_result.ok and abuse_result.data:
        try:
            result.abuse_score = int(abuse_result.data["data"]["abuseConfidenceScore"])
            cc = abuse_result.data["data"].get("countryCode")
            if cc and not result.country:
                result.country = cc
        except (KeyError, TypeError, ValueError):
            pass

    # ---- Determine overall status -----------------------------------
    any_ok = any(r.ok for r in provider_results)
    any_configured = any(r.status != STATUS_NOT_CONFIGURED for r in provider_results)
    all_unavailable = provider_results and not any(
        r.status in (STATUS_OK, STATUS_NOT_FOUND) for r in provider_results
    )

    if not provider_results:
        result.result_status = RESULT_NO_DATA
        result.explanation = "No providers support this IOC type in the current integration."
    elif not any_configured:
        result.result_status = RESULT_PROVIDERS_UNAVAILABLE
        result.explanation = "No relevant provider API key is configured for this IOC type."
    elif all_unavailable:
        result.result_status = RESULT_PROVIDERS_UNAVAILABLE
        result.explanation = "All relevant providers failed, were rate-limited, or rejected the API key. No verdict can be produced."
    elif any_ok:
        result.result_status = RESULT_VALID
    else:
        result.result_status = RESULT_NO_DATA
        result.explanation = "Providers responded but had no record for this indicator."

    # ---- Classification / severity / confidence -----------------------
    # Only computed when we actually have usable provider data. A failed
    # or unconfigured provider set never yields "Safe" — it yields
    # PROVIDERS UNAVAILABLE / NO DATA FOUND with Unknown classification.
    if result.result_status == RESULT_VALID:
        vt = result.vt_malicious_count or 0
        abuse = result.abuse_score if result.abuse_score is not None else None

        if vt >= 5 or (abuse is not None and abuse >= 80):
            result.classification, result.severity = "Malicious", "Critical"
        elif vt >= 1 or (abuse is not None and abuse >= 40):
            result.classification, result.severity = "Suspicious", "High"
        elif abuse is not None and abuse >= 10:
            result.classification, result.severity = "Suspicious", "Medium"
        else:
            result.classification, result.severity = "Clean", "Low"

        # Confidence reflects how many providers actually returned usable
        # data, not just whether the verdict looks bad.
        usable = sum(1 for r in provider_results if r.status in (STATUS_OK, STATUS_NOT_FOUND))
        result.confidence = "High" if usable >= 2 else ("Medium" if usable == 1 else "Low")

        parts = []
        if result.vt_malicious_count is not None:
            parts.append(f"VirusTotal: {result.vt_malicious_count} engine(s) flagged this indicator as malicious.")
        if result.abuse_score is not None:
            parts.append(f"AbuseIPDB confidence score: {result.abuse_score}/100.")
        if otx_result and otx_result.status == STATUS_NOT_CONFIGURED:
            parts.append("OTX enrichment not configured (optional).")
        elif otx_result and not otx_result.ok:
            parts.append(f"OTX enrichment unavailable ({otx_result.message})")
        result.explanation = " ".join(parts) if parts else "Providers returned no risk indicators."

    # ---- MITRE ATT&CK mapping (only where defensible) ------------------
    if result.classification in ("Malicious", "Suspicious"):
        result.mitre = mitre_mapper.map_ioc_classification(ioc_type, result.classification)

    return result
