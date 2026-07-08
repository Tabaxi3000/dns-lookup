"""
test_analysis.py

Tests for DNS tunneling and DGA detection heuristics (Challenges 7 and 9)

Tests:
  shannon_entropy boundary values and ordering
  analyze_subdomain flags encoded/long subdomains and clears normal ones
  looks_encoded charset and length behavior
  analyze_dga flags random-looking SLDs and clears real brands
  second_level_domain extraction

Connects to:
  analysis.py - the functions under test
"""

from dnslookup.analysis import (
    analyze_dga,
    analyze_subdomain,
    looks_encoded,
    second_level_domain,
    shannon_entropy,
)


class TestShannonEntropy:
    def test_empty_is_zero(self) -> None:
        """
        Empty input has zero entropy
        """
        assert shannon_entropy("") == 0.0

    def test_uniform_string_is_zero(self) -> None:
        """
        A single repeated character has zero entropy
        """
        assert shannon_entropy("aaaaaa") == 0.0

    def test_two_symbols_is_one_bit(self) -> None:
        """
        Two equally frequent symbols give one bit of entropy
        """
        assert shannon_entropy("abab") == 1.0

    def test_random_higher_than_word(self) -> None:
        """
        A random-looking string has higher entropy than a normal word
        """
        assert shannon_entropy("a8Xz9Qp2Lm") > shannon_entropy("example")


class TestTunnelDetection:
    def test_normal_subdomain_is_clean(self) -> None:
        """
        A normal subdomain is not flagged as tunneling
        """
        result = analyze_subdomain("www.example.com")
        assert result.suspicious is False

    def test_deep_normal_subdomain_is_clean(self) -> None:
        """
        A legitimate multi-label subdomain is not flagged
        """
        assert analyze_subdomain("cdn.assets.static.example.com").suspicious is False

    def test_encoded_subdomain_is_flagged(self) -> None:
        """
        A base64-looking subdomain is flagged as suspicious
        """
        result = analyze_subdomain("aGVsbG8gd29ybGQgdGVzdA.tunnel.attacker.com")
        assert result.suspicious is True
        assert result.encoded_label is True

    def test_long_label_is_flagged(self) -> None:
        """
        An overly long label is flagged with a reason
        """
        long_label = "a" * 50
        result = analyze_subdomain(f"{long_label}.evil.com")
        assert result.suspicious is True
        assert any("long label" in reason for reason in result.reasons)

    def test_looks_encoded(self) -> None:
        """
        looks_encoded requires length and a base64/hex charset
        """
        assert looks_encoded("aGVsbG8gd29ybGQgdGVzdGluZw") is True
        assert looks_encoded("short") is False
        assert looks_encoded("has spaces in it here yeah") is False


class TestDGADetection:
    def test_real_brands_are_clean(self) -> None:
        """
        Well-known domains are not flagged as DGA
        """
        for domain in ["google.com", "facebook.com", "microsoft.com",
                       "youtube.com", "cloudflare.com"]:
            assert analyze_dga(domain).is_dga is False, domain

    def test_random_consonants_flagged(self) -> None:
        """
        A high-consonant random SLD is flagged as DGA
        """
        result = analyze_dga("kwxqzvfhjlmnbp.com")
        assert result.is_dga is True
        assert result.consonant_ratio > 0.7

    def test_digit_heavy_flagged(self) -> None:
        """
        A digit-heavy SLD is flagged as DGA
        """
        assert analyze_dga("p8x2q9z7w3.info").is_dga is True

    def test_short_domain_not_flagged(self) -> None:
        """
        Very short SLDs are not judged (too little signal)
        """
        assert analyze_dga("bit.ly").is_dga is False

    def test_second_level_domain(self) -> None:
        """
        second_level_domain extracts the registrable label
        """
        assert second_level_domain("a.b.example.com") == "example"
        assert second_level_domain("example.com") == "example"
        assert second_level_domain("localhost") == "localhost"
