"""
log_parser.py
-------------
Repaired log-analysis engine. Replaces the app's previous behavior of only
recognizing the literal substring "SRC=". This module:

- Accepts raw text content plus a filename (to pick a parsing strategy for
  .txt/.log/.csv/.json), and degrades gracefully on malformed input instead
  of crashing or silently returning nothing.
- Applies regex-based pattern detection per line/record for a small,
  explicit set of genuinely observable categories.
- Extracts IPv4 addresses it finds as candidate IOCs (does not validate
  them against threat-intel providers itself — that's ioc_analysis.py's
  job, kept separate on purpose).
- Reports what it could and couldn't parse, rather than pretending every
  file was fully understood.
"""

from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field
from typing import Optional

import mitre_mapper

IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
TIMESTAMP_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\b|\b\d{2}:\d{2}:\d{2}\b"
)

# category -> (regex, severity). Kept intentionally small and explicit —
# each pattern corresponds to something genuinely observable in free-text
# log lines, not a guess.
PATTERNS: dict[str, tuple[re.Pattern, str]] = {
    "Brute Force": (re.compile(r"failed login|authentication failed|invalid password", re.I), "High"),
    "Malware Indicator": (re.compile(r"\bmalware\b|\btrojan\b|\bvirus\b|\bransomware\b", re.I), "Critical"),
    "Port Scan": (re.compile(r"\bnmap\b|port scan|\bsyn scan\b", re.I), "Medium"),
    "Privilege Escalation": (re.compile(r"\bsudo\b|admin access|privilege escalation", re.I), "High"),
}


@dataclass
class LogFinding:
    line_number: int
    category: str
    severity: str
    raw_line: str
    timestamp: Optional[str]
    extracted_ips: list[str] = field(default_factory=list)


@dataclass
class LogAnalysisResult:
    filename: str
    parse_ok: bool
    parse_message: str
    total_events: int = 0
    suspicious_events: int = 0
    findings: list[LogFinding] = field(default_factory=list)
    severity_counts: dict[str, int] = field(default_factory=dict)
    category_counts: dict[str, int] = field(default_factory=dict)
    extracted_iocs: set = field(default_factory=set)


def _analyze_line(line_number: int, line: str) -> Optional[LogFinding]:
    if not line.strip():
        return None

    matched_category = None
    matched_severity = None
    for category, (pattern, severity) in PATTERNS.items():
        if pattern.search(line):
            matched_category = category
            matched_severity = severity
            break  # first genuine match wins; a line is reported once

    if not matched_category:
        return None

    ts_match = TIMESTAMP_RE.search(line)
    ips = IPV4_RE.findall(line)

    return LogFinding(
        line_number=line_number,
        category=matched_category,
        severity=matched_severity,
        raw_line=line.strip()[:500],  # cap stored raw line length
        timestamp=ts_match.group(0) if ts_match else None,
        extracted_ips=ips,
    )


def _iter_lines_from_text(content: str):
    for i, line in enumerate(content.splitlines(), start=1):
        yield i, line


def _iter_lines_from_csv(content: str):
    reader = csv.reader(io.StringIO(content))
    for i, row in enumerate(reader, start=1):
        yield i, ",".join(row)


def _iter_lines_from_json(content: str):
    """Supports either a JSON array of objects/strings, or JSON Lines
    (one JSON object per line). Falls back to raising if neither parses,
    which the caller turns into a graceful parse_ok=False result."""
    stripped = content.strip()
    if not stripped:
        return []
    try:
        parsed = json.loads(stripped)
        if isinstance(parsed, list):
            lines = []
            for i, entry in enumerate(parsed, start=1):
                lines.append((i, json.dumps(entry) if not isinstance(entry, str) else entry))
            return lines
    except json.JSONDecodeError:
        pass

    # Try JSON Lines
    lines = []
    for i, raw in enumerate(stripped.splitlines(), start=1):
        raw = raw.strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
            lines.append((i, json.dumps(obj)))
        except json.JSONDecodeError:
            raise ValueError(f"Line {i} is not valid JSON.")
    return lines


def parse_log(filename: str, raw_bytes: bytes) -> LogAnalysisResult:
    """Entry point. Never raises — always returns a LogAnalysisResult, with
    parse_ok=False and a human-readable parse_message if the file couldn't
    be understood at all."""
    lower_name = (filename or "").lower()

    try:
        content = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        try:
            content = raw_bytes.decode("latin-1")
        except Exception as exc:
            return LogAnalysisResult(
                filename=filename, parse_ok=False,
                parse_message=f"Could not decode file as text: {exc}",
            )

    try:
        if lower_name.endswith(".csv"):
            line_iter = list(_iter_lines_from_csv(content))
        elif lower_name.endswith(".json"):
            line_iter = _iter_lines_from_json(content)
        else:
            # .txt, .log, and anything else: treat as plain text
            line_iter = list(_iter_lines_from_text(content))
    except Exception as exc:
        return LogAnalysisResult(
            filename=filename, parse_ok=False,
            parse_message=f"File could not be parsed as {lower_name.rsplit('.', 1)[-1] if '.' in lower_name else 'text'}: {exc}",
        )

    result = LogAnalysisResult(filename=filename, parse_ok=True, parse_message="Parsed successfully.")
    result.total_events = len(line_iter)

    for line_number, line in line_iter:
        finding = _analyze_line(line_number, line)
        if finding:
            result.findings.append(finding)
            result.severity_counts[finding.severity] = result.severity_counts.get(finding.severity, 0) + 1
            result.category_counts[finding.category] = result.category_counts.get(finding.category, 0) + 1
            result.extracted_iocs.update(finding.extracted_ips)

    result.suspicious_events = len(result.findings)

    if result.total_events == 0:
        result.parse_ok = False
        result.parse_message = "File was read but contained no parsable lines/records."

    return result
