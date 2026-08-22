"""
yara_engine.py
---------------
Local YARA rule matching for uploaded files. Genuinely functional when the
`yara-python` package and `rules/malware_rules.yar` are both available —
degrades to a clearly labeled "unavailable" state otherwise instead of
silently doing nothing or faking a match.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

RULES_PATH = os.path.join(os.path.dirname(__file__), "rules", "malware_rules.yar")

STATUS_READY = "READY"
STATUS_NOT_INSTALLED = "YARA_NOT_INSTALLED"
STATUS_RULES_MISSING = "RULES_FILE_MISSING"
STATUS_COMPILE_ERROR = "RULES_COMPILE_ERROR"

_compiled_rules = None
_status = None
_status_message = ""


def _init():
    global _compiled_rules, _status, _status_message
    if _status is not None:
        return  # already attempted

    try:
        import yara
    except ImportError:
        _status = STATUS_NOT_INSTALLED
        _status_message = "The 'yara-python' package is not installed — YARA scanning is disabled."
        return

    if not os.path.exists(RULES_PATH):
        _status = STATUS_RULES_MISSING
        _status_message = f"YARA rules file not found at {RULES_PATH} — YARA scanning is disabled."
        return

    try:
        _compiled_rules = yara.compile(filepath=RULES_PATH)
        _status = STATUS_READY
        _status_message = "YARA engine ready."
    except Exception as exc:
        _status = STATUS_COMPILE_ERROR
        _status_message = f"Failed to compile YARA rules: {exc}"


@dataclass
class YaraScanResult:
    status: str
    message: str
    matches: list[str] = field(default_factory=list)


def engine_status() -> tuple[str, str]:
    """Returns (status, message) without performing a scan — used by the
    Provider Status / Settings page."""
    _init()
    return _status, _status_message


def scan_bytes(file_bytes: bytes) -> YaraScanResult:
    _init()

    if _status != STATUS_READY:
        return YaraScanResult(status=_status, message=_status_message, matches=[])

    try:
        matches = _compiled_rules.match(data=file_bytes)
        return YaraScanResult(
            status=STATUS_READY,
            message="Scan completed.",
            matches=[m.rule for m in matches],
        )
    except Exception as exc:
        return YaraScanResult(status=STATUS_COMPILE_ERROR, message=f"YARA scan failed: {exc}", matches=[])
