"""
api_client.py
-------------
Single place for all outbound HTTP calls to threat-intel providers.

Every provider function returns a ProviderResult with an explicit status,
instead of ever silently collapsing a failure into "0 / Safe / clean".
Statuses are one of:

    OK                  - request succeeded, `data` holds the parsed payload
    NOT_CONFIGURED       - no API key available for this provider
    INVALID_KEY          - provider rejected the credential (401/403)
    RATE_LIMITED         - provider returned 429
    NOT_FOUND            - provider has no record for this IOC (still valid)
    PROVIDER_ERROR        - provider returned an unexpected HTTP status
    NETWORK_ERROR         - timeout, connection error, or malformed response

Nothing here ever fabricates a result if a call fails.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional

import requests

from config import REQUEST_TIMEOUT_SECONDS, CACHE_TTL_SECONDS

STATUS_OK = "OK"
STATUS_NOT_CONFIGURED = "NOT_CONFIGURED"
STATUS_INVALID_KEY = "INVALID_KEY"
STATUS_RATE_LIMITED = "RATE_LIMITED"
STATUS_NOT_FOUND = "NOT_FOUND"
STATUS_PROVIDER_ERROR = "PROVIDER_ERROR"
STATUS_NETWORK_ERROR = "NETWORK_ERROR"


@dataclass
class ProviderResult:
    provider: str
    status: str
    data: Optional[dict] = None
    message: str = ""

    @property
    def ok(self) -> bool:
        return self.status == STATUS_OK


# Tiny in-process cache: (provider, method, url, frozenset(params)) -> (expiry, ProviderResult)
# Only successful (OK / NOT_FOUND) results are cached — errors are never
# cached, so a transient outage doesn't get "remembered" as a verdict.
_cache: dict[tuple, tuple[float, ProviderResult]] = {}


def _cache_key(provider: str, url: str, params: Optional[dict]) -> tuple:
    frozen_params = tuple(sorted((params or {}).items()))
    return (provider, url, frozen_params)


def _get(provider: str, url: str, headers: Optional[dict] = None,
          params: Optional[dict] = None, use_cache: bool = True) -> ProviderResult:
    key = _cache_key(provider, url, params)

    if use_cache and key in _cache:
        expiry, cached = _cache[key]
        if time.time() < expiry:
            return cached

    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    except requests.exceptions.Timeout:
        return ProviderResult(provider, STATUS_NETWORK_ERROR, message="Request timed out.")
    except requests.exceptions.RequestException as exc:
        return ProviderResult(provider, STATUS_NETWORK_ERROR, message=f"Network error: {exc}")

    if response.status_code in (401, 403):
        return ProviderResult(provider, STATUS_INVALID_KEY,
                               message="Provider rejected the API key.")
    if response.status_code == 429:
        return ProviderResult(provider, STATUS_RATE_LIMITED,
                               message="Provider rate limit exceeded.")
    if response.status_code == 404:
        result = ProviderResult(provider, STATUS_NOT_FOUND, message="No record found.")
        if use_cache:
            _cache[key] = (time.time() + CACHE_TTL_SECONDS, result)
        return result
    if response.status_code != 200:
        return ProviderResult(provider, STATUS_PROVIDER_ERROR,
                               message=f"Unexpected HTTP {response.status_code}.")

    try:
        payload = response.json()
    except ValueError:
        return ProviderResult(provider, STATUS_NETWORK_ERROR,
                               message="Provider returned a malformed (non-JSON) response.")

    result = ProviderResult(provider, STATUS_OK, data=payload)
    if use_cache:
        _cache[key] = (time.time() + CACHE_TTL_SECONDS, result)
    return result


# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------

def virustotal_ip(ip: str, api_key: Optional[str]) -> ProviderResult:
    if not api_key:
        return ProviderResult("VirusTotal", STATUS_NOT_CONFIGURED,
                               message="No VirusTotal API key configured.")
    return _get(
        "VirusTotal",
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": api_key},
    )


def virustotal_domain(domain: str, api_key: Optional[str]) -> ProviderResult:
    if not api_key:
        return ProviderResult("VirusTotal", STATUS_NOT_CONFIGURED,
                               message="No VirusTotal API key configured.")
    return _get(
        "VirusTotal",
        f"https://www.virustotal.com/api/v3/domains/{domain}",
        headers={"x-apikey": api_key},
    )


def virustotal_url(url_value: str, api_key: Optional[str]) -> ProviderResult:
    """VT's URL endpoint requires a URL-identifier submit step; without that
    submission, only a best-effort lookup via the file/url analysis endpoint
    can be attempted. Kept honest: a lookup-only path is used, and a
    NOT_FOUND result simply means VT has no cached verdict yet."""
    if not api_key:
        return ProviderResult("VirusTotal", STATUS_NOT_CONFIGURED,
                               message="No VirusTotal API key configured.")
    import base64
    url_id = base64.urlsafe_b64encode(url_value.encode()).decode().strip("=")
    return _get(
        "VirusTotal",
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers={"x-apikey": api_key},
    )


def virustotal_file_hash(file_hash: str, api_key: Optional[str]) -> ProviderResult:
    if not api_key:
        return ProviderResult("VirusTotal", STATUS_NOT_CONFIGURED,
                               message="No VirusTotal API key configured.")
    return _get(
        "VirusTotal",
        f"https://www.virustotal.com/api/v3/files/{file_hash}",
        headers={"x-apikey": api_key},
    )


# ---------------------------------------------------------------------------
# AbuseIPDB (IP addresses only — never call this for domains/URLs/hashes)
# ---------------------------------------------------------------------------

def abuseipdb_check(ip: str, api_key: Optional[str]) -> ProviderResult:
    if not api_key:
        return ProviderResult("AbuseIPDB", STATUS_NOT_CONFIGURED,
                               message="No AbuseIPDB API key configured.")
    return _get(
        "AbuseIPDB",
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": api_key, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": "90"},
    )


# ---------------------------------------------------------------------------
# AlienVault OTX (optional provider — see README "OTX status")
# ---------------------------------------------------------------------------

def otx_ip(ip: str, api_key: Optional[str]) -> ProviderResult:
    if not api_key:
        return ProviderResult("OTX", STATUS_NOT_CONFIGURED,
                               message="OTX_API_KEY is not configured (optional provider).")
    return _get(
        "OTX",
        f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
        headers={"X-OTX-API-KEY": api_key},
    )


def otx_domain(domain: str, api_key: Optional[str]) -> ProviderResult:
    if not api_key:
        return ProviderResult("OTX", STATUS_NOT_CONFIGURED,
                               message="OTX_API_KEY is not configured (optional provider).")
    return _get(
        "OTX",
        f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
        headers={"X-OTX-API-KEY": api_key},
    )
