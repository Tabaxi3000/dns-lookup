"""
querylog.py

Query logging setup and log-line formatting (Challenge 2)

Configures a dedicated "dnslookup.query" logger that writes structured
query records to a file, and provides pure formatting helpers that turn a
query request and its DNSResult into log lines. The resolver calls these
around each lookup so that domains queried, record types, timing, and
record counts are recorded for later analysis.

Key exports:
  QUERY_LOGGER_NAME - Name of the shared query logger
  get_logger() - Returns the shared query logger
  setup_query_logging() - Attaches a file handler when a log path is given
  format_query_start() - Formats the pre-query log line
  format_query_complete() - Formats the post-query log line

Connects to:
  resolver.py - lookup() logs start/complete lines through this logger
  cli.py - query and batch commands call setup_query_logging(--log-file)
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable
    from pathlib import Path

    from dnslookup.resolver import DNSResult, RecordType

QUERY_LOGGER_NAME = "dnslookup.query"


def get_logger() -> logging.Logger:
    """
    Return the shared query logger
    """
    return logging.getLogger(QUERY_LOGGER_NAME)


def setup_query_logging(log_file: Path | None) -> logging.Logger:
    """
    Configure the query logger to write to a file when a path is provided
    """
    logger = get_logger()
    logger.setLevel(logging.INFO)

    if log_file is not None:
        handler: logging.Handler = logging.FileHandler(
            log_file,
            encoding = "utf-8",
        )
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        )
        logger.addHandler(handler)

    return logger


def format_query_start(
    domain: str,
    record_types: Iterable[RecordType],
) -> str:
    """
    Format the log line emitted before a query is sent
    """
    types = ",".join(rt.value for rt in record_types)
    return f"QUERY domain={domain} types={types}"


def format_query_complete(result: DNSResult) -> str:
    """
    Format the log line emitted after a query completes
    """
    return (
        f"RESULT domain={result.domain} "
        f"records={len(result.records)} "
        f"errors={len(result.errors)} "
        f"time_ms={result.query_time_ms:.1f} "
        f"nameserver={result.nameserver or '-'}"
    )
