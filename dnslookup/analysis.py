"""
analysis.py

DNS threat-analysis heuristics: tunneling and DGA detection

Pure, offline heuristics for spotting suspicious domains. Tunnel
detection (Challenge 7) flags subdomains that look like encoded data
using Shannon entropy, label length, and character-set checks. DGA
detection (Challenge 9) flags algorithmically generated domains using
consonant ratio, vowel ratio, digit ratio, and entropy of the
second-level domain. Neither performs any network I/O, so both are fully
unit-testable.

Key exports:
  shannon_entropy() - Shannon entropy (bits per character) of a string
  SubdomainAnalysis / analyze_subdomain() - DNS tunneling indicators
  DGAAnalysis / analyze_dga() - Domain-generation-algorithm indicators

Connects to:
  cli.py - the analyze command renders these results
  output.py - printers for SubdomainAnalysis and DGAAnalysis
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field

# DNS single-label length limit (RFC 1035); labels longer than this are invalid.
DNS_LABEL_MAX = 63

# Above this entropy a label is unusually random, suggesting encoded data.
TUNNEL_ENTROPY_THRESHOLD = 3.5

# A label at least this long is suspicious for a human-readable subdomain.
TUNNEL_LENGTH_THRESHOLD = 40

VOWELS = frozenset("aeiou")
CONSONANTS = frozenset("bcdfghjklmnpqrstvwxyz")
_BASE64_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_"
)


def shannon_entropy(text: str) -> float:
    """
    Shannon entropy in bits per character; 0.0 for empty input
    """
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def _labels(fqdn: str) -> list[str]:
    """
    Split a domain into its dot-separated labels, dropping empties
    """
    return [label for label in fqdn.split(".") if label]


def looks_encoded(label: str) -> bool:
    """
    True when a label is long and drawn only from base64/hex-style characters
    """
    if len(label) < 16:
        return False
    return all(char in _BASE64_CHARS for char in label)


@dataclass
class SubdomainAnalysis:
    """
    Result of analyzing a domain for DNS tunneling indicators
    """
    fqdn: str
    entropy: float
    longest_label: int
    encoded_label: bool
    suspicious: bool
    reasons: list[str] = field(default_factory = list)


def analyze_subdomain(
    fqdn: str,
    entropy_threshold: float = TUNNEL_ENTROPY_THRESHOLD,
    length_threshold: int = TUNNEL_LENGTH_THRESHOLD,
) -> SubdomainAnalysis:
    """
    Analyze a fully qualified domain for DNS tunneling indicators
    """
    labels = _labels(fqdn)
    # Only the subdomain labels matter; the registrable domain (last two
    # labels) is not attacker-controlled data.
    sub_labels = labels[:-2] if len(labels) > 2 else []

    joined = "".join(sub_labels)
    entropy = shannon_entropy(joined)
    longest_label = max((len(label) for label in labels), default = 0)
    encoded = any(looks_encoded(label) for label in sub_labels)

    reasons: list[str] = []
    if joined and entropy >= entropy_threshold:
        reasons.append(f"high subdomain entropy ({entropy:.2f})")
    if longest_label >= length_threshold:
        reasons.append(f"long label ({longest_label} chars)")
    if longest_label > DNS_LABEL_MAX:
        reasons.append(f"label exceeds DNS limit ({longest_label} > {DNS_LABEL_MAX})")
    if encoded:
        reasons.append("encoded-looking subdomain label")

    return SubdomainAnalysis(
        fqdn = fqdn,
        entropy = entropy,
        longest_label = longest_label,
        encoded_label = encoded,
        suspicious = bool(reasons),
        reasons = reasons,
    )


def second_level_domain(domain: str) -> str:
    """
    Return the second-level label of a domain (e.g. 'example' in a.example.com)
    """
    labels = _labels(domain)
    if len(labels) >= 2:
        return labels[-2]
    return labels[0] if labels else ""


def _ratio(text: str, members: frozenset[str]) -> float:
    """
    Fraction of alphabetic-or-digit characters that belong to a set
    """
    if not text:
        return 0.0
    return sum(1 for char in text.lower() if char in members) / len(text)


@dataclass
class DGAAnalysis:
    """
    Result of analyzing a domain for domain-generation-algorithm indicators
    """
    domain: str
    sld: str
    entropy: float
    consonant_ratio: float
    vowel_ratio: float
    digit_ratio: float
    is_dga: bool
    reasons: list[str] = field(default_factory = list)


def analyze_dga(domain: str) -> DGAAnalysis:
    """
    Analyze a domain's second-level label for DGA characteristics
    """
    sld = second_level_domain(domain)
    entropy = shannon_entropy(sld)
    consonant_ratio = _ratio(sld, CONSONANTS)
    vowel_ratio = _ratio(sld, VOWELS)
    digit_ratio = _ratio(sld, frozenset("0123456789"))

    reasons: list[str] = []
    # Short labels are too small to judge reliably.
    if len(sld) >= 7:
        if consonant_ratio > 0.7:
            reasons.append(f"high consonant ratio ({consonant_ratio:.0%})")
        if vowel_ratio < 0.25 and entropy > 3.0:
            reasons.append(f"low vowel ratio ({vowel_ratio:.0%})")
        if entropy > 3.8:
            reasons.append(f"high entropy ({entropy:.2f})")
        if digit_ratio > 0.3:
            reasons.append(f"digit-heavy ({digit_ratio:.0%})")

    return DGAAnalysis(
        domain = domain,
        sld = sld,
        entropy = entropy,
        consonant_ratio = consonant_ratio,
        vowel_ratio = vowel_ratio,
        digit_ratio = digit_ratio,
        is_dga = bool(reasons),
        reasons = reasons,
    )
