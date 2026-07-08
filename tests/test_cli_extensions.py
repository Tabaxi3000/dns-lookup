"""
test_cli_extensions.py

Integration tests for the extension CLI commands and flags

Networked commands (query, enum, passive add) are monkeypatched so the
tests run offline; purely local commands (analyze, covert, passive
history) run directly.

Tests:
  query --csv emits CSV rows
  analyze reports tunneling/DGA verdicts and JSON
  covert-encode/covert-decode round-trip through the CLI
  enum renders discovered subdomains (mocked resolver)
  passive history/resolutions read from a prepopulated database

Connects to:
  cli.py - the Typer app under test
"""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from dnslookup import cli
from dnslookup.enumeration import SubdomainHit
from dnslookup.passive import PassiveDNSStore
from dnslookup.resolver import DNSRecord, DNSResult, RecordType

runner = CliRunner()


async def _fake_lookup(
    domain: str,
    record_types: object = None,
    nameserver: str | None = None,
    timeout: float = 5.0,
) -> DNSResult:
    return DNSResult(
        domain = domain,
        records = [DNSRecord(RecordType.A, "1.2.3.4", 300)],
        query_time_ms = 1.0,
        nameserver = nameserver,
    )


async def _fake_enum(
    domain: str,
    wordlist: object = None,
    nameserver: str | None = None,
    timeout: float = 3.0,
) -> list[SubdomainHit]:
    return [SubdomainHit(fqdn = f"www.{domain}", addresses = ["1.2.3.4"])]


class TestQueryCsv:
    def test_csv_flag(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """
        query --csv prints the CSV header and record value
        """
        monkeypatch.setattr(cli, "lookup", _fake_lookup)
        result = runner.invoke(cli.app, ["query", "example.com", "--csv"])
        assert result.exit_code == 0
        assert "domain,record_type,value" in result.output
        assert "1.2.3.4" in result.output


class TestAnalyze:
    def test_dga_domain(self) -> None:
        """
        analyze flags a random-looking domain as DGA
        """
        result = runner.invoke(cli.app, ["analyze", "kwxqzvfhjlmnbp.com"])
        assert result.exit_code == 0
        assert "DGA" in result.output

    def test_json(self) -> None:
        """
        analyze --json returns parseable analysis with both sections
        """
        import json

        result = runner.invoke(
            cli.app,
            ["analyze", "aGVsbG8gd29ybGQ.tunnel.evil.com", "--json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["tunneling"]["suspicious"] is True
        assert "dga" in data


class TestCovertCli:
    def test_roundtrip(self) -> None:
        """
        covert-encode then covert-decode recovers the message
        """
        encoded = runner.invoke(
            cli.app,
            ["covert-encode", "hello", "--domain", "t.evil.com"],
        )
        token = encoded.output.strip()
        decoded = runner.invoke(
            cli.app,
            ["covert-decode", token, "--domain", "t.evil.com"],
        )
        assert decoded.exit_code == 0
        assert "hello" in decoded.output

    def test_txt_roundtrip(self) -> None:
        """
        covert-encode --txt then covert-decode --txt recovers the message
        """
        encoded = runner.invoke(cli.app, ["covert-encode", "data", "--txt"])
        token = encoded.output.strip()
        decoded = runner.invoke(cli.app, ["covert-decode", token, "--txt"])
        assert "data" in decoded.output


class TestEnumCli:
    def test_enum(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """
        enum renders the discovered subdomains from the resolver
        """
        monkeypatch.setattr(cli, "enumerate_subdomains", _fake_enum)
        result = runner.invoke(cli.app, ["enum", "example.com"])
        assert result.exit_code == 0
        assert "www.example.com" in result.output


class TestPassiveCli:
    def test_history_and_resolutions(self, tmp_path: Path) -> None:
        """
        passive history/resolutions read records from a prepopulated database
        """
        db_path = tmp_path / "passive.db"
        store = PassiveDNSStore(str(db_path))
        store.record("example.com", "A", "1.2.3.4", 300)
        store.record("other.com", "A", "1.2.3.4", 300)
        store.close()

        history = runner.invoke(
            cli.app,
            ["passive", "history", "example.com", "--db", str(db_path)],
        )
        assert history.exit_code == 0
        assert "1.2.3.4" in history.output

        resolutions = runner.invoke(
            cli.app,
            ["passive", "resolutions", "1.2.3.4", "--db", str(db_path)],
        )
        assert resolutions.exit_code == 0
        assert "example.com" in resolutions.output
        assert "other.com" in resolutions.output
