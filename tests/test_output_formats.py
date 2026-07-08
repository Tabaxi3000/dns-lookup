"""
test_output_formats.py

Tests for CSV output formatting (Challenge 3)

Tests:
  header row and column order
  one row per record with priority column populated for MX
  domains with no records still produce a row
  multiple domains are flattened together

Connects to:
  output.py - results_to_csv under test
  resolver.py - DNSResult/DNSRecord used to build input
"""

import csv
import io

from dnslookup.output import CSV_COLUMNS, results_to_csv
from dnslookup.resolver import DNSRecord, DNSResult, RecordType


def _rows(csv_text: str) -> list[list[str]]:
    return list(csv.reader(io.StringIO(csv_text)))


class TestResultsToCsv:
    def test_header(self) -> None:
        """
        The first row is the expected header
        """
        result = DNSResult(domain = "example.com")
        rows = _rows(results_to_csv(result))
        assert rows[0] == CSV_COLUMNS

    def test_record_rows(self) -> None:
        """
        Each record becomes a row and MX priority is included
        """
        result = DNSResult(
            domain = "example.com",
            records = [
                DNSRecord(RecordType.A, "1.2.3.4", 86400),
                DNSRecord(RecordType.MX, "mail.example.com", 3600, priority = 10),
            ],
            query_time_ms = 45.2,
        )
        rows = _rows(results_to_csv(result))
        assert rows[1] == ["example.com", "A", "1.2.3.4", "86400", "", "45.2"]
        assert rows[2][1] == "MX"
        assert rows[2][4] == "10"

    def test_empty_domain_row(self) -> None:
        """
        A domain with no records still produces a single row
        """
        result = DNSResult(domain = "nodata.example.com", query_time_ms = 12.0)
        rows = _rows(results_to_csv(result))
        assert len(rows) == 2
        assert rows[1][0] == "nodata.example.com"
        assert rows[1][1] == ""

    def test_multiple_domains(self) -> None:
        """
        A list of results is flattened into one CSV
        """
        results = [
            DNSResult(
                domain = "a.com",
                records = [DNSRecord(RecordType.A, "1.1.1.1", 300)],
            ),
            DNSResult(
                domain = "b.com",
                records = [DNSRecord(RecordType.A, "2.2.2.2", 300)],
            ),
        ]
        rows = _rows(results_to_csv(results))
        domains = {row[0] for row in rows[1:]}
        assert domains == {"a.com", "b.com"}
