"""
test_querylog.py

Tests for query logging setup and formatting (Challenge 2)

Tests:
  format_query_start includes domain and record types
  format_query_complete includes record count and timing
  setup_query_logging writes emitted records to the given file

Connects to:
  querylog.py - the functions under test
  resolver.py - DNSResult/RecordType used to build inputs
"""

from pathlib import Path

from dnslookup.querylog import (
    QUERY_LOGGER_NAME,
    format_query_complete,
    format_query_start,
    get_logger,
    setup_query_logging,
)
from dnslookup.resolver import DNSRecord, DNSResult, RecordType


class TestFormatting:
    def test_format_query_start(self) -> None:
        """
        The start line names the domain and the comma-joined record types
        """
        line = format_query_start("example.com", [RecordType.A, RecordType.MX])
        assert "domain=example.com" in line
        assert "types=A,MX" in line

    def test_format_query_complete(self) -> None:
        """
        The complete line reports record count, errors, and timing
        """
        result = DNSResult(
            domain = "example.com",
            records = [DNSRecord(RecordType.A, "1.2.3.4", 300)],
            query_time_ms = 42.0,
            nameserver = "8.8.8.8",
        )
        line = format_query_complete(result)
        assert "domain=example.com" in line
        assert "records=1" in line
        assert "time_ms=42.0" in line
        assert "nameserver=8.8.8.8" in line


class TestSetupLogging:
    def test_writes_to_file(self, tmp_path: Path) -> None:
        """
        A configured file handler writes emitted log lines to disk
        """
        log_file = tmp_path / "queries.log"
        logger = setup_query_logging(log_file)
        try:
            logger.info("QUERY domain=example.com types=A")
            for handler in logger.handlers:
                handler.flush()
            contents = log_file.read_text()
            assert "QUERY domain=example.com" in contents
        finally:
            # Detach the file handler so other tests keep a clean logger.
            for handler in list(logger.handlers):
                handler.close()
                logger.removeHandler(handler)

    def test_no_file_adds_no_handler(self) -> None:
        """
        Calling setup without a path does not attach a file handler
        """
        logger = get_logger()
        before = len(logger.handlers)
        setup_query_logging(None)
        assert len(logger.handlers) == before
        assert logger.name == QUERY_LOGGER_NAME
