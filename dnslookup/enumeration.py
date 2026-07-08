"""
enumeration.py

Subdomain enumeration by wordlist brute force (Challenge 4)

Generates candidate subdomains from a wordlist and resolves them
concurrently, reporting the ones that exist. Candidate generation and
result filtering are pure functions so they can be tested without
network access; the enumeration coroutine reuses the resolver's
batch_lookup for the actual queries.

Key exports:
  COMMON_SUBDOMAINS - Default brute-force wordlist
  SubdomainHit - A discovered subdomain and its A-record addresses
  generate_candidates() - Build candidate FQDNs from a domain and wordlist
  hits_from_results() - Filter DNSResults down to resolvable subdomains
  enumerate_subdomains() - Async brute-force enumeration for a domain

Connects to:
  resolver.py - uses batch_lookup and RecordType
  cli.py - the enum command
"""

from __future__ import annotations

from dataclasses import dataclass, field

from dnslookup.resolver import DNSResult, RecordType, batch_lookup

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "imap", "admin",
    "administrator", "test", "dev", "staging", "stage", "api", "api2",
    "app", "apps", "portal", "vpn", "remote", "ns1", "ns2", "dns",
    "mx", "mx1", "cdn", "static", "assets", "img", "images", "media",
    "blog", "shop", "store", "secure", "login", "auth", "sso", "git",
    "gitlab", "jenkins", "ci", "docker", "registry", "db", "database",
    "mysql", "postgres", "redis", "cache", "internal", "intranet",
    "corp", "vpn2", "gateway", "proxy", "monitor", "grafana", "kibana",
    "status", "support", "help", "docs", "wiki", "beta", "demo", "m",
    "mobile", "cpanel", "whm", "webdisk", "autodiscover", "owa",
]


@dataclass
class SubdomainHit:
    """
    A discovered subdomain and the A-record addresses it resolves to
    """
    fqdn: str
    addresses: list[str] = field(default_factory = list)


def generate_candidates(
    domain: str,
    wordlist: list[str] | None = None,
) -> list[str]:
    """
    Build candidate FQDNs by prefixing each wordlist entry onto the domain
    """
    words = wordlist if wordlist is not None else COMMON_SUBDOMAINS
    base = domain.strip(".")
    return [f"{word}.{base}" for word in words]


def hits_from_results(results: list[DNSResult]) -> list[SubdomainHit]:
    """
    Reduce DNSResults to the subdomains that returned at least one A record
    """
    hits: list[SubdomainHit] = []
    for result in results:
        addresses = [
            record.value
            for record in result.records
            if record.record_type == RecordType.A
        ]
        if addresses:
            hits.append(
                SubdomainHit(fqdn = result.domain, addresses = addresses)
            )
    return hits


async def enumerate_subdomains(
    domain: str,
    wordlist: list[str] | None = None,
    nameserver: str | None = None,
    timeout: float = 3.0,
) -> list[SubdomainHit]:
    """
    Brute-force enumerate subdomains of a domain using a wordlist
    """
    candidates = generate_candidates(domain, wordlist)
    results = await batch_lookup(
        candidates,
        [RecordType.A],
        nameserver,
        timeout,
    )
    return hits_from_results(results)
