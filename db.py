"""
db.py
-----
Lightweight SQLite persistence for investigation history. Stores only
non-secret investigation metadata/results — never API keys, never raw
provider responses containing anything beyond what's summarized here.
"""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS investigations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    kind TEXT NOT NULL,               -- 'IOC' or 'LOG' or 'FILE'
    ioc_value TEXT,
    ioc_type TEXT,
    classification TEXT,
    severity TEXT,
    result_status TEXT,
    provider_summary TEXT,            -- JSON string, non-secret summary only
    findings_summary TEXT             -- JSON string, non-secret summary only
);
"""


def _ensure_dir():
    directory = os.path.dirname(DB_PATH)
    if directory:
        os.makedirs(directory, exist_ok=True)


@contextmanager
def _connect():
    _ensure_dir()
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(SCHEMA)
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with _connect():
        pass


def record_investigation(
    kind: str,
    ioc_value: Optional[str] = None,
    ioc_type: Optional[str] = None,
    classification: Optional[str] = None,
    severity: Optional[str] = None,
    result_status: Optional[str] = None,
    provider_summary: Optional[dict] = None,
    findings_summary: Optional[dict] = None,
) -> int:
    with _connect() as conn:
        cur = conn.execute(
            """INSERT INTO investigations
               (timestamp, kind, ioc_value, ioc_type, classification, severity,
                result_status, provider_summary, findings_summary)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                datetime.utcnow().isoformat(timespec="seconds") + "Z",
                kind,
                ioc_value,
                ioc_type,
                classification,
                severity,
                result_status,
                json.dumps(provider_summary or {}),
                json.dumps(findings_summary or {}),
            ),
        )
        return cur.lastrowid


def fetch_recent(limit: int = 50) -> list[sqlite3.Row]:
    with _connect() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM investigations ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return rows


def fetch_dashboard_counts() -> dict:
    """Aggregate counts for the Dashboard page, computed only from what's
    actually been persisted — never an artificial/incrementing value."""
    with _connect() as conn:
        total = conn.execute("SELECT COUNT(*) FROM investigations").fetchone()[0]
        critical = conn.execute(
            "SELECT COUNT(*) FROM investigations WHERE severity = 'Critical'"
        ).fetchone()[0]
        high = conn.execute(
            "SELECT COUNT(*) FROM investigations WHERE severity = 'High'"
        ).fetchone()[0]
        suspicious = conn.execute(
            "SELECT COUNT(*) FROM investigations WHERE classification IN ('Suspicious', 'Malicious')"
        ).fetchone()[0]
        by_classification = conn.execute(
            "SELECT COALESCE(classification, 'Unknown') as c, COUNT(*) FROM investigations GROUP BY c"
        ).fetchall()
        return {
            "total": total,
            "critical": critical,
            "high": high,
            "suspicious": suspicious,
            "by_classification": dict(by_classification),
        }
