"""
test_enumeration.py

Tests for subdomain enumeration candidate generation and filtering (Challenge 4)

These are offline tests of the pure helpers; the live enumerate_subdomains
coroutine is exercised indirectly via the CLI extension tests.

Tests:
  generate_candidates builds FQDNs from the default and custom wordlists
  hits_from_results keeps only domains with A records

Connects to:
  enumeration.py - the functions under test
  resolver.py - DNSResult/DNSRecord used to build fake results
"""

from dnslookup.enumeration import (
    COMMON_SUBDOMAINS,
    generate_candidates,
    hits_from_results,
)
from dnslookup.resolver import DNSRecord, DNSResult, RecordType


class TestGenerateCandidates:
    def test_default_wordlist(self) -> None:
        """
        Default candidates cover the built-in wordlist and include www
        """
        candidates = generate_candidates("example.com")
        assert len(candidates) == len(COMMON_SUBDOMAINS)
        assert "www.example.com" in candidates

    def test_custom_wordlist(self) -> None:
        """
        A custom wordlist produces exactly the requested FQDNs
        """
        candidates = generate_candidates("example.com", ["api", "dev"])
        assert candidates == ["api.example.com", "dev.example.com"]

    def test_strips_trailing_dot(self) -> None:
        """
        A trailing dot on the domain is normalized away
        """
        assert generate_candidates("example.com.", ["www"]) == ["www.example.com"]


class TestHitsFromResults:
    def test_keeps_only_resolvable(self) -> None:
        """
        Only results that returned A records become hits
        """
        results = [
            DNSResult(
                domain = "www.example.com",
                records = [DNSRecord(RecordType.A, "1.2.3.4", 300)],
            ),
            DNSResult(domain = "missing.example.com", records = []),
        ]
        hits = hits_from_results(results)
        assert len(hits) == 1
        assert hits[0].fqdn == "www.example.com"
        assert hits[0].addresses == ["1.2.3.4"]

    def test_collects_multiple_addresses(self) -> None:
        """
        Multiple A records are collected onto a single hit
        """
        results = [
            DNSResult(
                domain = "www.example.com",
                records = [
                    DNSRecord(RecordType.A, "1.2.3.4", 300),
                    DNSRecord(RecordType.A, "5.6.7.8", 300),
                ],
            ),
        ]
        hits = hits_from_results(results)
        assert hits[0].addresses == ["1.2.3.4", "5.6.7.8"]

    def test_empty(self) -> None:
        """
        No results yields no hits
        """
        assert hits_from_results([]) == []
