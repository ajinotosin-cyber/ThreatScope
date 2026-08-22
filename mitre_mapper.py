"""
mitre_mapper.py
----------------
Maps ThreatScope's own detections (log-parser categories, IOC
classifications) to MITRE ATT&CK techniques. Only mappings with a
defensible, documented relationship are included — this module does not
attempt to map every possible finding, and callers should treat an empty
list as a legitimate "no defensible mapping" result rather than a bug.

Mappings are limited to Enterprise ATT&CK techniques that plausibly
correspond to what the log parser / IOC classifier can actually observe
from log text or a provider verdict; they are not a substitute for a real
detection-engineering mapping exercise.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MitreTechnique:
    technique_id: str
    technique_name: str
    tactic: str
    explanation: str


# Findings emitted by log_parser.py -> MITRE technique(s).
_LOG_CATEGORY_MAP: dict[str, list[MitreTechnique]] = {
    "Brute Force": [
        MitreTechnique(
            "T1110", "Brute Force", "Credential Access",
            "Repeated authentication failures against the same account/service "
            "are the direct observable of a brute-force credential-guessing attempt.",
        )
    ],
    "Port Scan": [
        MitreTechnique(
            "T1046", "Network Service Discovery", "Discovery",
            "Sequential connection attempts across multiple ports/hosts (e.g. nmap "
            "signatures in logs) are consistent with active service enumeration.",
        )
    ],
    "Privilege Escalation": [
        MitreTechnique(
            "T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation",
            "Use of sudo/admin-access grants outside expected patterns is consistent "
            "with an attempt to elevate privileges via legitimate OS mechanisms.",
        )
    ],
    "Malware Indicator": [
        MitreTechnique(
            "T1204", "User Execution", "Execution",
            "Log references to malware/trojan/virus activity commonly correspond to "
            "execution of a malicious payload, typically following user interaction "
            "or a dropper.",
        )
    ],
}

# IOC classification -> MITRE technique(s). Deliberately conservative: an IOC
# verdict alone (e.g. "this IP is malicious per VirusTotal") supports a
# general Command and Control / infrastructure inference, not a specific
# technique like a particular exploit.
_IOC_CLASSIFICATION_MAP: dict[tuple[str, str], list[MitreTechnique]] = {
    ("IPv4", "Malicious"): [
        MitreTechnique(
            "T1071", "Application Layer Protocol", "Command and Control",
            "An IP address with a high-confidence malicious verdict from threat-intel "
            "providers is commonly associated with C2 or malicious-infrastructure "
            "communication.",
        )
    ],
    ("Domain", "Malicious"): [
        MitreTechnique(
            "T1071", "Application Layer Protocol", "Command and Control",
            "A domain flagged malicious by threat-intel providers is commonly used "
            "for C2 or phishing infrastructure.",
        )
    ],
    ("URL", "Malicious"): [
        MitreTechnique(
            "T1566", "Phishing", "Initial Access",
            "A malicious URL verdict is commonly associated with phishing delivery "
            "infrastructure.",
        )
    ],
    ("SHA256 Hash", "Malicious"): [
        MitreTechnique(
            "T1204", "User Execution", "Execution",
            "A file hash flagged malicious by AV engines corresponds to a known "
            "malicious binary, typically requiring execution to have impact.",
        )
    ],
}


def map_log_finding(category: str) -> list[MitreTechnique]:
    """Return MITRE techniques for a log_parser.py finding category, or an
    empty list if there is no defensible mapping for it."""
    return list(_LOG_CATEGORY_MAP.get(category, []))


def map_ioc_classification(ioc_type: str, classification: str) -> list[MitreTechnique]:
    """Return MITRE techniques for an IOC investigation classification, or
    an empty list if there is no defensible mapping.

    Deliberately does not map "Suspicious" verdicts — a mid-confidence
    signal isn't strong enough to defensibly attribute a specific ATT&CK
    technique, so only "Malicious" classifications are mapped.
    """
    return list(_IOC_CLASSIFICATION_MAP.get((ioc_type, classification), []))


# Backward-compatible simple lookup (kept for any external callers expecting
# the old flat interface: category name -> technique ID string only).
def map_attack(event: str) -> str:
    techniques = map_log_finding(event)
    return techniques[0].technique_id if techniques else "Unknown"
