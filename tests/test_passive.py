"""
test_passive.py

Tests for the passive DNS SQLite store (Challenge 8)

All tests run against an in-memory or temporary SQLite database, so no
network access is required.

Tests:
  record inserts a new row and updates seen_count/last_seen on repeat
  record_result ingests a DNSResult
  history returns a domain's records newest-first
  resolutions finds every domain for a value
  first_seen returns the original observation time

Connects to:
  passive.py - PassiveDNSStore under test
  resolver.py - DNSResult/DNSRecord used to build input
"""

from pathlib import Path

from dnslookup.passive import PassiveDNSStore
from dnslookup.resolver import DNSRecord, DNSResult, RecordType


class TestRecord:
    def test_insert_new(self) -> None:
        """
        A new observation is stored with seen_count 1
        """
        store = PassiveDNSStore()
        store.record("example.com", "A", "1.2.3.4", 300, now = "2026-01-01T00:00:00")
        history = store.history("example.com")
        assert len(history) == 1
        assert history[0].seen_count == 1
        store.close()

    def test_repeat_increments_count(self) -> None:
        """
        Re-observing the same record increments the count and updates last_seen
        """
        store = PassiveDNSStore()
        store.record("example.com", "A", "1.2.3.4", 300, now = "2026-01-01T00:00:00")
        store.record("example.com", "A", "1.2.3.4", 300, now = "2026-01-05T00:00:00")
        record = store.history("example.com")[0]
        assert record.seen_count == 2
        assert record.first_seen == "2026-01-01T00:00:00"
        assert record.last_seen == "2026-01-05T00:00:00"
        store.close()

    def test_persists_to_file(self, tmp_path: Path) -> None:
        """
        Records survive closing and reopening a file-backed store
        """
        db_path = tmp_path / "passive.db"
        store = PassiveDNSStore(str(db_path))
        store.record("example.com", "A", "1.2.3.4", 300)
        store.close()

        reopened = PassiveDNSStore(str(db_path))
        assert len(reopened.history("example.com")) == 1
        reopened.close()


class TestRecordResult:
    def test_ingests_dnsresult(self) -> None:
        """
        record_result stores every record and returns the count
        """
        store = PassiveDNSStore()
        result = DNSResult(
            domain = "example.com",
            records = [
                DNSRecord(RecordType.A, "1.2.3.4", 300),
                DNSRecord(RecordType.MX, "mail.example.com", 3600, priority = 10),
            ],
        )
        assert store.record_result(result) == 2
        assert len(store.history("example.com")) == 2
        store.close()


class TestQueries:
    def _populated_store(self) -> PassiveDNSStore:
        store = PassiveDNSStore()
        store.record("example.com", "A", "1.2.3.4", 300, now = "2026-01-01T00:00:00")
        store.record("example.com", "A", "5.6.7.8", 300, now = "2026-01-03T00:00:00")
        store.record("other.com", "A", "1.2.3.4", 300, now = "2026-01-02T00:00:00")
        return store

    def test_history_newest_first(self) -> None:
        """
        History is ordered by last_seen descending
        """
        store = self._populated_store()
        history = store.history("example.com")
        assert [r.value for r in history] == ["5.6.7.8", "1.2.3.4"]
        store.close()

    def test_resolutions_finds_all_domains(self) -> None:
        """
        resolutions returns every domain that resolved to a value
        """
        store = self._populated_store()
        domains = {r.domain for r in store.resolutions("1.2.3.4")}
        assert domains == {"example.com", "other.com"}
        store.close()

    def test_first_seen(self) -> None:
        """
        first_seen returns the earliest observation timestamp
        """
        store = self._populated_store()
        assert store.first_seen("example.com", "1.2.3.4") == "2026-01-01T00:00:00"
        assert store.first_seen("example.com", "9.9.9.9") is None
        store.close()
