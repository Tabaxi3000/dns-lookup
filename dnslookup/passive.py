"""
passive.py

Passive DNS historical store backed by SQLite (Challenge 8)

Records every (domain, record type, value) observation with first-seen /
last-seen timestamps and a seen count, so the tool can answer historical
questions: when a domain first resolved to an address, which domains have
pointed at a given value, and how often a record has been observed. Uses
only the standard-library sqlite3 module and is fully offline-testable
against an in-memory or temporary database.

Key exports:
  PassiveRecord - One stored observation row
  PassiveDNSStore - SQLite-backed store with record and query methods

Connects to:
  resolver.py - record_result() ingests DNSResult objects
  cli.py - the passive command group
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime

from dnslookup.resolver import DNSResult

_SCHEMA = """
CREATE TABLE IF NOT EXISTS dns_records (
    id INTEGER PRIMARY KEY,
    domain TEXT NOT NULL,
    record_type TEXT NOT NULL,
    value TEXT NOT NULL,
    ttl INTEGER,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    seen_count INTEGER NOT NULL DEFAULT 1,
    UNIQUE(domain, record_type, value)
);
CREATE INDEX IF NOT EXISTS idx_domain ON dns_records(domain);
CREATE INDEX IF NOT EXISTS idx_value ON dns_records(value);
"""


@dataclass
class PassiveRecord:
    """
    A single stored passive-DNS observation
    """
    domain: str
    record_type: str
    value: str
    ttl: int | None
    first_seen: str
    last_seen: str
    seen_count: int


def _now_iso() -> str:
    """
    Current UTC time as an ISO 8601 string
    """
    return datetime.now(UTC).isoformat()


class PassiveDNSStore:
    """
    SQLite-backed historical store of DNS resolutions
    """
    def __init__(self, path: str = ":memory:") -> None:
        """
        Open (or create) the store at the given path
        """
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def record(
        self,
        domain: str,
        record_type: str,
        value: str,
        ttl: int | None = None,
        now: str | None = None,
    ) -> None:
        """
        Insert a new observation or update the existing one's last_seen/count
        """
        timestamp = now or _now_iso()
        self.conn.execute(
            """
            INSERT INTO dns_records
                (domain, record_type, value, ttl, first_seen, last_seen, seen_count)
            VALUES (?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(domain, record_type, value) DO UPDATE SET
                last_seen = excluded.last_seen,
                ttl = excluded.ttl,
                seen_count = seen_count + 1
            """,
            (domain, record_type, value, ttl, timestamp, timestamp),
        )
        self.conn.commit()

    def record_result(self, result: DNSResult, now: str | None = None) -> int:
        """
        Store every record from a DNSResult; returns the number stored
        """
        count = 0
        for record in result.records:
            self.record(
                domain = result.domain,
                record_type = record.record_type.value,
                value = record.value,
                ttl = record.ttl,
                now = now,
            )
            count += 1
        return count

    def _rows_to_records(
        self,
        rows: list[sqlite3.Row],
    ) -> list[PassiveRecord]:
        return [
            PassiveRecord(
                domain = row["domain"],
                record_type = row["record_type"],
                value = row["value"],
                ttl = row["ttl"],
                first_seen = row["first_seen"],
                last_seen = row["last_seen"],
                seen_count = row["seen_count"],
            )
            for row in rows
        ]

    def history(self, domain: str) -> list[PassiveRecord]:
        """
        Return all stored records for a domain, most recently seen first
        """
        rows = self.conn.execute(
            "SELECT * FROM dns_records WHERE domain = ? ORDER BY last_seen DESC",
            (domain,),
        ).fetchall()
        return self._rows_to_records(rows)

    def resolutions(self, value: str) -> list[PassiveRecord]:
        """
        Return all domains that have resolved to the given value (e.g. an IP)
        """
        rows = self.conn.execute(
            "SELECT * FROM dns_records WHERE value = ? ORDER BY domain",
            (value,),
        ).fetchall()
        return self._rows_to_records(rows)

    def first_seen(self, domain: str, value: str) -> str | None:
        """
        Return when a specific domain/value pair was first observed
        """
        row = self.conn.execute(
            "SELECT first_seen FROM dns_records WHERE domain = ? AND value = ?",
            (domain, value),
        ).fetchone()
        return row["first_seen"] if row else None

    def close(self) -> None:
        """
        Close the underlying database connection
        """
        self.conn.close()
