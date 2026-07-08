"""
test_covert.py

Tests for DNS covert-channel encoding/decoding (Challenge 14)

Tests:
  query encode/decode roundtrip for text, empty, and binary payloads
  encoded labels respect the 63-character DNS label limit
  encoded query characters are all DNS-label safe
  response (TXT) encode/decode roundtrip

Connects to:
  covert.py - the functions under test
"""

import string

from dnslookup.covert import (
    MAX_LABEL_LENGTH,
    decode_query,
    decode_response,
    encode_query,
    encode_response,
)

_LABEL_SAFE = set(string.ascii_letters + string.digits + "-_")


class TestQueryEncoding:
    def test_roundtrip_text(self) -> None:
        """
        A text payload survives an encode/decode roundtrip
        """
        data = b"secret exfil payload"
        fqdn = encode_query(data, "tunnel.evil.com")
        assert decode_query(fqdn, "tunnel.evil.com") == data

    def test_roundtrip_empty(self) -> None:
        """
        Empty data round-trips to empty bytes
        """
        fqdn = encode_query(b"", "tunnel.evil.com")
        assert decode_query(fqdn, "tunnel.evil.com") == b""

    def test_roundtrip_binary(self) -> None:
        """
        All 256 byte values survive a roundtrip
        """
        data = bytes(range(256))
        fqdn = encode_query(data, "t.evil.com")
        assert decode_query(fqdn, "t.evil.com") == data

    def test_labels_within_dns_limit(self) -> None:
        """
        Every encoded label stays within the DNS 63-character limit
        """
        data = bytes(range(256))
        fqdn = encode_query(data, "t.evil.com")
        assert all(len(label) <= MAX_LABEL_LENGTH for label in fqdn.split("."))

    def test_encoded_chars_are_label_safe(self) -> None:
        """
        The encoded subdomain uses only DNS-label-safe characters
        """
        data = bytes(range(256))
        fqdn = encode_query(data, "t.evil.com")
        subdomain = fqdn[: -len(".t.evil.com")]
        assert all(char in _LABEL_SAFE for char in subdomain.replace(".", ""))

    def test_appends_base_domain(self) -> None:
        """
        The base domain appears as the suffix of the encoded FQDN
        """
        assert encode_query(b"hi", "tunnel.evil.com").endswith(".tunnel.evil.com")


class TestResponseEncoding:
    def test_roundtrip(self) -> None:
        """
        A TXT-record payload round-trips through base64
        """
        data = b"command: sleep 60"
        assert decode_response(encode_response(data)) == data

    def test_decode_strips_quotes(self) -> None:
        """
        Decoding tolerates surrounding quotes from a raw TXT record
        """
        encoded = encode_response(b"data")
        assert decode_response(f'"{encoded}"') == b"data"
