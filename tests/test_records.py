"""
test_records.py

Tests for the security-oriented record types (Challenge 12)

Record values are extracted from rdata objects built offline with
dns.rdata.from_text, so no network access is required.

Tests:
  the new record types exist on the RecordType enum
  ALL_RECORD_TYPES still excludes the specialized types (7 entries)
  extract_record_value produces readable values for CAA/SSHFP/TLSA/DNSKEY/DS

Connects to:
  resolver.py - RecordType and extract_record_value under test
"""

import dns.rdata
import dns.rdataclass
import dns.rdatatype

from dnslookup.resolver import ALL_RECORD_TYPES, RecordType, extract_record_value


def _rdata(rtype: str, text: str) -> dns.rdata.Rdata:
    return dns.rdata.from_text(
        dns.rdataclass.IN,
        dns.rdatatype.from_text(rtype),
        text,
    )


class TestNewRecordTypes:
    def test_types_exist(self) -> None:
        """
        The new security record types are present on the enum
        """
        assert RecordType.CAA == "CAA"
        assert RecordType.SSHFP == "SSHFP"
        assert RecordType.TLSA == "TLSA"
        assert RecordType.DNSKEY == "DNSKEY"
        assert RecordType.DS == "DS"

    def test_all_record_types_unchanged(self) -> None:
        """
        The default lookup set still has 7 types and excludes the new ones
        """
        assert len(ALL_RECORD_TYPES) == 7
        assert RecordType.CAA not in ALL_RECORD_TYPES
        assert RecordType.DNSKEY not in ALL_RECORD_TYPES


class TestExtraction:
    def test_caa(self) -> None:
        """
        CAA extraction yields a readable 'flags tag "value"' string
        """
        rdata = _rdata("CAA", '0 issue "letsencrypt.org"')
        value, priority = extract_record_value(rdata, RecordType.CAA)
        assert value == '0 issue "letsencrypt.org"'
        assert priority is None

    def test_sshfp(self) -> None:
        """
        SSHFP extraction yields the algorithm/type/fingerprint text
        """
        fp = "abcdef0123456789abcdef0123456789abcdef01"
        value, _ = extract_record_value(_rdata("SSHFP", f"1 1 {fp}"), RecordType.SSHFP)
        assert value == f"1 1 {fp}"

    def test_tlsa(self) -> None:
        """
        TLSA extraction yields the usage/selector/matching/cert text
        """
        value, _ = extract_record_value(
            _rdata("TLSA", "3 1 1 0123456789abcdef"),
            RecordType.TLSA,
        )
        assert value.startswith("3 1 1 ")

    def test_dnskey(self) -> None:
        """
        DNSKEY extraction yields the flags/protocol/algorithm/key text
        """
        value, _ = extract_record_value(
            _rdata("DNSKEY", "256 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvk"),
            RecordType.DNSKEY,
        )
        assert value.startswith("256 3 8 ")

    def test_ds(self) -> None:
        """
        DS extraction yields the key-tag/algorithm/digest-type/digest text
        """
        digest = "a" * 64
        value, _ = extract_record_value(
            _rdata("DS", f"12345 8 2 {digest}"),
            RecordType.DS,
        )
        assert value.startswith("12345 8 2 ")
