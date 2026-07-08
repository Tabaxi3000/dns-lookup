"""
covert.py

DNS covert-channel encoding/decoding (Challenge 14, research/education)

Encodes arbitrary bytes into DNS-safe subdomain labels for the
client-to-server direction and into base64 TXT payloads for the
server-to-client direction, plus the matching decoders. Uses URL-safe
base64 without padding so every character is a legal DNS label
character, and splits into 63-character labels to respect the DNS label
limit. Pure functions with no network I/O.

Key exports:
  encode_query() - Encode bytes into a query FQDN under a base domain
  decode_query() - Recover bytes from a query FQDN
  encode_response() - Encode bytes into a base64 TXT payload
  decode_response() - Recover bytes from a base64 TXT payload

Connects to:
  cli.py - covert-encode and covert-decode commands

Ethical note: only for use on infrastructure you own or are authorized to
test. Unauthorized DNS tunneling is illegal.
"""

from __future__ import annotations

import base64

# DNS single-label length limit (RFC 1035).
MAX_LABEL_LENGTH = 63


def _split_labels(encoded: str) -> list[str]:
    """
    Split an encoded string into DNS labels of at most MAX_LABEL_LENGTH
    """
    return [
        encoded[i: i + MAX_LABEL_LENGTH]
        for i in range(0, len(encoded), MAX_LABEL_LENGTH)
    ]


def encode_query(data: bytes, domain: str) -> str:
    """
    Encode bytes into a query FQDN of the form <b64-labels>.<domain>
    """
    encoded = base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")
    labels = _split_labels(encoded)
    base = domain.strip(".")
    if not labels:
        return base
    return ".".join(labels) + "." + base


def decode_query(fqdn: str, domain: str) -> bytes:
    """
    Recover the bytes encoded in a query FQDN under the given base domain
    """
    base = domain.strip(".")
    suffix = "." + base
    if fqdn == base:
        subdomain = ""
    elif fqdn.endswith(suffix):
        subdomain = fqdn[: -len(suffix)]
    else:
        subdomain = fqdn

    encoded = subdomain.replace(".", "")
    padding = "=" * (-len(encoded) % 4)
    return base64.urlsafe_b64decode(encoded + padding)


def encode_response(data: bytes) -> str:
    """
    Encode bytes into a base64 TXT-record payload
    """
    return base64.b64encode(data).decode("ascii")


def decode_response(txt_record: str) -> bytes:
    """
    Recover bytes from a base64 TXT-record payload
    """
    return base64.b64decode(txt_record.strip().strip('"'))
