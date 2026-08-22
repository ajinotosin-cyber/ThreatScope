"""
config.py
---------
Centralized configuration and credential loading for ThreatScope.

Design rules (do not violate):
- Never hardcode a credential in this file or any other source file.
- Read credentials from Streamlit Cloud secrets (`st.secrets`) when running
  under Streamlit, falling back to process environment variables (populated
  from a local, git-ignored `.env` file via python-dotenv) for local dev.
- Never require a `.env` file to exist in production.
- Never log, print, or return raw credential values anywhere in the app.
  Only boolean "is configured" state and provider status labels are exposed
  to the UI.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from dotenv import load_dotenv

# Loads a local .env file if present (no-op if it doesn't exist — this is
# expected and fine in production, where secrets come from Streamlit Cloud).
load_dotenv()

# Canonical environment variable / secret key names used throughout the app.
# There is exactly ONE name per credential — the old project's bug where
# threat_lookup.py and .env disagreed on the AbuseIPDB variable name is
# fixed by having a single source of truth here.
VIRUSTOTAL_API_KEY = "VIRUSTOTAL_API_KEY"
ABUSEIPDB_API_KEY = "ABUSEIPDB_API_KEY"
OTX_API_KEY = "OTX_API_KEY"

REQUIRED_KEYS = (VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY)
OPTIONAL_KEYS = (OTX_API_KEY,)


def _get_secret(name: str) -> Optional[str]:
    """
    Look up a credential by name, preferring Streamlit Cloud secrets and
    falling back to environment variables. Returns None (not an empty
    string) when unset, so callers can distinguish "not configured" from
    "configured but empty".
    """
    value = None

    # st.secrets is only meaningfully populated when running under
    # `streamlit run`, and raises/behaves oddly if no secrets.toml exists
    # locally — so this is wrapped defensively rather than imported at
    # module load time in a way that could crash a non-Streamlit context
    # (e.g. the test suite, or train_model.py).
    try:
        import streamlit as st  # local import: keep this module importable
        # without Streamlit installed, e.g. from plain test scripts.
        if hasattr(st, "secrets") and name in st.secrets:
            value = st.secrets[name]
    except Exception:
        value = None

    if not value:
        value = os.getenv(name)

    if value:
        value = str(value).strip()

    return value or None


@dataclass(frozen=True)
class ProviderConfig:
    virustotal_key: Optional[str]
    abuseipdb_key: Optional[str]
    otx_key: Optional[str]

    @property
    def virustotal_configured(self) -> bool:
        return self.virustotal_key is not None

    @property
    def abuseipdb_configured(self) -> bool:
        return self.abuseipdb_key is not None

    @property
    def otx_configured(self) -> bool:
        return self.otx_key is not None


def load_provider_config() -> ProviderConfig:
    """Load all provider credentials once per call. Cheap — safe to call
    freely; Streamlit will typically call this once per script run."""
    return ProviderConfig(
        virustotal_key=_get_secret(VIRUSTOTAL_API_KEY),
        abuseipdb_key=_get_secret(ABUSEIPDB_API_KEY),
        otx_key=_get_secret(OTX_API_KEY),
    )


# Shared HTTP behavior
REQUEST_TIMEOUT_SECONDS = 8
CACHE_TTL_SECONDS = 600  # successful lookups only — see api_client.py

# Where persisted investigation history lives.
DB_PATH = os.getenv("THREATSCOPE_DB_PATH", "data/threatscope.db")
