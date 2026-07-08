"""
cli.py

Typer CLI application for DNS lookups

Defines the dnslookup CLI using Typer with five commands: query, reverse,
trace, batch, and whois. Each command shows a Rich spinner during the
operation, then either renders formatted terminal output or JSON depending
on the --json flag. The batch command also supports writing JSON to a file
with --output.

Key exports:
  app - The Typer application instance, used as the entry point in __main__.py

Connects to:
  resolver.py - calls lookup(), reverse_lookup(), trace_dns(), batch_lookup()
  output.py - calls all print_* functions and results_to_json(), trace_to_json()
  whois_lookup.py - calls lookup_whois(), print_whois_result(), whois_to_json()
  __init__.py - imports __version__ for the --version flag
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Annotated

import typer
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
)

from dnslookup import __version__
from dnslookup.analysis import analyze_dga, analyze_subdomain
from dnslookup.covert import (
    decode_query,
    decode_response,
    encode_query,
    encode_response,
)
from dnslookup.enumeration import enumerate_subdomains
from dnslookup.output import (
    console,
    print_analysis,
    print_batch_progress_header,
    print_batch_results,
    print_enum_results,
    print_errors,
    print_header,
    print_passive_records,
    print_results_table,
    print_reverse_result,
    print_summary,
    print_trace_result,
    results_to_csv,
    results_to_json,
    trace_to_json,
)
from dnslookup.passive import PassiveDNSStore
from dnslookup.querylog import setup_query_logging
from dnslookup.resolver import (
    ALL_RECORD_TYPES,
    RecordType,
    batch_lookup,
    lookup,
    reverse_lookup,
    trace_dns,
)
from dnslookup.whois_lookup import (
    lookup_whois,
    print_whois_result,
    whois_to_json,
)

app = typer.Typer(
    name = "dnslookup",
    help =
    "[bold green]DNS Lookup Tool[/bold green] - Professional DNS query CLI with clean output",
    rich_markup_mode = "rich",
    no_args_is_help = True,
)


def version_callback(value: bool) -> None:
    """
    Display version and exit
    """
    if value:
        console.print(
            f"[bold cyan]dnslookup[/bold cyan] version [green]{__version__}[/green]"
        )
        raise typer.Exit()


def parse_record_types(types_str: str) -> list[RecordType]:
    """
    Parse comma separated record types string
    """
    if types_str.upper() == "ALL":
        return list(ALL_RECORD_TYPES)

    types = []
    for t in types_str.upper().split(","):
        t = t.strip()
        try:
            types.append(RecordType(t))
        except ValueError:
            console.print(
                f"[yellow]Warning:[/yellow] Unknown record type '{t}', skipping"
            )

    return types if types else list(ALL_RECORD_TYPES)


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option(
            "--version",
            "-v",
            help = "Show version and exit",
            callback = version_callback,
            is_eager = True,
        ),
    ] = None,
) -> None:
    """
    [bold green]DNS Lookup Tool[/bold green]

    Query DNS records, perform reverse lookups, trace resolution paths,
    and retrieve WHOIS information with nice terminal output.
    """
    pass


@app.command()
def query(
    domain: Annotated[str,
                      typer.Argument(help = "Domain name to query")],
    record_type: Annotated[
        str,
        typer.Option(
            "--type",
            "-t",
            help =
            "Record types to query (A,AAAA,MX,NS,TXT,CNAME,SOA or ALL)",
        ),
    ] = "ALL",
    server: Annotated[
        str | None,
        typer.Option(
            "--server",
            "-s",
            help = "DNS server to use (e.g., 8.8.8.8)",
        ),
    ] = None,
    timeout: Annotated[
        float,
        typer.Option(
            "--timeout",
            help = "Query timeout in seconds",
        ),
    ] = 5.0,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            "-j",
            help = "Output results as JSON",
        ),
    ] = False,
    csv_output: Annotated[
        bool,
        typer.Option(
            "--csv",
            help = "Output results as CSV",
        ),
    ] = False,
    log_file: Annotated[
        Path | None,
        typer.Option(
            "--log-file",
            help = "Append query log lines to this file",
        ),
    ] = None,
) -> None:
    """
    [bold cyan]Query DNS records[/bold cyan] for a domain.

    Examples:
        dnslookup query example.com
        dnslookup query example.com --type A,MX,CAA
        dnslookup query example.com --server 8.8.8.8 --json
        dnslookup query example.com --csv
    """
    setup_query_logging(log_file)
    record_types = parse_record_types(record_type)

    with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console = console,
            transient = True,
    ) as progress:
        progress.add_task(f"Querying {domain}...", total = None)
        result = asyncio.run(
            lookup(domain,
                   record_types,
                   server,
                   timeout)
        )

    if json_output:
        console.print(results_to_json(result))
    elif csv_output:
        console.print(results_to_csv(result))
    else:
        print_header(domain)
        print_results_table(result)
        print_errors(result)
        print_summary(result)


@app.command()
def reverse(
    ip: Annotated[
        str,
        typer.Argument(help = "IP address for reverse lookup")],
    server: Annotated[
        str | None,
        typer.Option(
            "--server",
            "-s",
            help = "DNS server to use",
        ),
    ] = None,
    timeout: Annotated[
        float,
        typer.Option(
            "--timeout",
            help = "Query timeout in seconds",
        ),
    ] = 5.0,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            "-j",
            help = "Output results as JSON",
        ),
    ] = False,
    csv_output: Annotated[
        bool,
        typer.Option(
            "--csv",
            help = "Output results as CSV",
        ),
    ] = False,
) -> None:
    """
    [bold cyan]Reverse DNS lookup[/bold cyan] for an IP address.

    Examples:
        dnslookup reverse 8.8.8.8
        dnslookup reverse 2606:4700:4700::1111
    """
    with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console = console,
            transient = True,
    ) as progress:
        progress.add_task(f"Resolving {ip}...", total = None)
        result = asyncio.run(reverse_lookup(ip, server, timeout))

    if json_output:
        console.print(results_to_json(result))
    elif csv_output:
        console.print(results_to_csv(result))
    else:
        print_reverse_result(result)


@app.command()
def trace(
    domain: Annotated[str,
                      typer.Argument(help = "Domain to trace")],
    record_type: Annotated[
        str,
        typer.Option(
            "--type",
            "-t",
            help = "Record type to trace (default: A)",
        ),
    ] = "A",
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            "-j",
            help = "Output results as JSON",
        ),
    ] = False,
) -> None:
    """
    [bold cyan]Trace DNS resolution path[/bold cyan] from root to authoritative servers.

    Shows the complete resolution chain including root servers, TLD servers,
    and authoritative nameservers.

    Examples:
        dnslookup trace example.com
        dnslookup trace example.com --type MX
    """
    with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console = console,
            transient = True,
    ) as progress:
        progress.add_task(f"Tracing {domain}...", total = None)
        result = trace_dns(domain, record_type.upper())

    if json_output:
        console.print(trace_to_json(result))
    else:
        print_trace_result(result)


@app.command()
def batch(
    file: Annotated[
        Path,
        typer.
        Argument(help = "File containing domains (one per line)"),
    ],
    record_type: Annotated[
        str,
        typer.Option(
            "--type",
            "-t",
            help = "Record types to query",
        ),
    ] = "A,MX,NS",
    server: Annotated[
        str | None,
        typer.Option(
            "--server",
            "-s",
            help = "DNS server to use",
        ),
    ] = None,
    timeout: Annotated[
        float,
        typer.Option(
            "--timeout",
            help = "Query timeout in seconds",
        ),
    ] = 5.0,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help = "Output file for JSON results",
        ),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            "-j",
            help = "Output results as JSON to stdout",
        ),
    ] = False,
    csv_output: Annotated[
        bool,
        typer.Option(
            "--csv",
            help = "Output results as CSV to stdout",
        ),
    ] = False,
    log_file: Annotated[
        Path | None,
        typer.Option(
            "--log-file",
            help = "Append query log lines to this file",
        ),
    ] = None,
) -> None:
    """
    [bold cyan]Batch DNS lookup[/bold cyan] for multiple domains from a file.

    The file should contain one domain per line. Empty lines and lines
    starting with # are ignored.

    Examples:
        dnslookup batch domains.txt
        dnslookup batch domains.txt --type A,MX --output results.json
        dnslookup batch domains.txt --csv
    """
    if not file.exists():
        console.print(f"[red]Error:[/red] File not found: {file}")
        raise typer.Exit(1)

    setup_query_logging(log_file)

    domains = []
    with open(file) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                domains.append(line)

    if not domains:
        console.print(
            "[yellow]Warning:[/yellow] No domains found in file"
        )
        raise typer.Exit(0)

    record_types = parse_record_types(record_type)

    with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console = console,
            transient = True,
    ) as progress:
        progress.add_task(
            f"Querying {len(domains)} domains...",
            total = None
        )
        results = asyncio.run(
            batch_lookup(domains,
                         record_types,
                         server,
                         timeout)
        )

    if json_output:
        console.print(results_to_json(results))
    elif csv_output:
        console.print(results_to_csv(results))
    elif output:
        with open(output, "w") as f:
            f.write(results_to_json(results))
        console.print(
            f"[green]:heavy_check_mark:[/green] Results saved to {output}"
        )
    else:
        print_batch_progress_header(len(domains))
        print_batch_results(results)


@app.command()
def whois(
    domain: Annotated[str,
                      typer.Argument(help = "Domain to lookup")],
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            "-j",
            help = "Output results as JSON",
        ),
    ] = False,
) -> None:
    """
    [bold cyan]WHOIS lookup[/bold cyan] for domain registration information.

    Shows registrar, creation date, expiration date, name servers,
    and other registration details.

    Examples:
        dnslookup whois example.com
        dnslookup whois google.com --json
    """
    with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console = console,
            transient = True,
    ) as progress:
        progress.add_task(
            f"Looking up WHOIS for {domain}...",
            total = None
        )
        result = lookup_whois(domain)

    if json_output:
        console.print(whois_to_json(result))
    else:
        print_whois_result(result)


@app.command()
def enum(
    domain: Annotated[str,
                      typer.Argument(help = "Domain to enumerate subdomains for")],
    server: Annotated[
        str | None,
        typer.Option("--server", "-s", help = "DNS server to use"),
    ] = None,
    timeout: Annotated[
        float,
        typer.Option("--timeout", help = "Query timeout in seconds"),
    ] = 3.0,
    json_output: Annotated[
        bool,
        typer.Option("--json", "-j", help = "Output results as JSON"),
    ] = False,
) -> None:
    """
    [bold cyan]Enumerate subdomains[/bold cyan] via wordlist brute force.

    Resolves a list of common subdomain names and reports the ones that
    exist. Only run this against domains you are authorized to test.

    Examples:
        dnslookup enum example.com
        dnslookup enum example.com --server 1.1.1.1 --json
    """
    with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console = console,
            transient = True,
    ) as progress:
        progress.add_task(f"Enumerating {domain}...", total = None)
        hits = asyncio.run(enumerate_subdomains(domain, None, server, timeout))

    if json_output:
        payload = [
            {"fqdn": hit.fqdn, "addresses": hit.addresses} for hit in hits
        ]
        console.print(json.dumps(payload, indent = 2))
    else:
        print_enum_results(domain, hits)


@app.command()
def analyze(
    domain: Annotated[str,
                      typer.Argument(help = "Domain to analyze for threats")],
    json_output: Annotated[
        bool,
        typer.Option("--json", "-j", help = "Output results as JSON"),
    ] = False,
) -> None:
    """
    [bold cyan]Analyze a domain[/bold cyan] for DNS tunneling and DGA indicators.

    Runs offline heuristics (entropy, label length, consonant/vowel ratios)
    to flag encoded subdomains and algorithmically generated domains.

    Examples:
        dnslookup analyze aGVsbG8.tunnel.evil.com
        dnslookup analyze kwxqzvfhjlmnbp.com --json
    """
    tunnel = analyze_subdomain(domain)
    dga = analyze_dga(domain)

    if json_output:
        payload = {
            "domain": domain,
            "tunneling": {
                "suspicious": tunnel.suspicious,
                "entropy": round(tunnel.entropy, 3),
                "longest_label": tunnel.longest_label,
                "encoded_label": tunnel.encoded_label,
                "reasons": tunnel.reasons,
            },
            "dga": {
                "is_dga": dga.is_dga,
                "sld": dga.sld,
                "entropy": round(dga.entropy, 3),
                "consonant_ratio": round(dga.consonant_ratio, 3),
                "vowel_ratio": round(dga.vowel_ratio, 3),
                "digit_ratio": round(dga.digit_ratio, 3),
                "reasons": dga.reasons,
            },
        }
        console.print(json.dumps(payload, indent = 2))
    else:
        print_analysis(domain, tunnel, dga)


@app.command(name = "covert-encode")
def covert_encode(
    message: Annotated[str,
                       typer.Argument(help = "Message to encode")],
    domain: Annotated[
        str,
        typer.Option("--domain", "-d", help = "Base domain for query encoding"),
    ] = "tunnel.example.com",
    txt: Annotated[
        bool,
        typer.Option("--txt", help = "Encode as a base64 TXT payload instead"),
    ] = False,
) -> None:
    """
    [bold cyan]Encode a message[/bold cyan] into a DNS covert-channel form.

    For research and education on infrastructure you own only.
    """
    data = message.encode("utf-8")
    if txt:
        console.print(encode_response(data))
    else:
        console.print(encode_query(data, domain))


@app.command(name = "covert-decode")
def covert_decode(
    payload: Annotated[str,
                       typer.Argument(help = "Encoded FQDN or TXT payload")],
    domain: Annotated[
        str,
        typer.Option("--domain", "-d", help = "Base domain for query decoding"),
    ] = "tunnel.example.com",
    txt: Annotated[
        bool,
        typer.Option("--txt", help = "Decode a base64 TXT payload instead"),
    ] = False,
) -> None:
    """
    [bold cyan]Decode a message[/bold cyan] from a DNS covert-channel form.
    """
    try:
        data = decode_response(payload) if txt else decode_query(payload, domain)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1) from None
    console.print(data.decode("utf-8", errors = "replace"))


passive_app = typer.Typer(
    help = "Passive DNS historical database commands",
    no_args_is_help = True,
)
app.add_typer(passive_app, name = "passive")


@passive_app.command("add")
def passive_add(
    domain: Annotated[str,
                      typer.Argument(help = "Domain to query and store")],
    record_type: Annotated[
        str,
        typer.Option("--type", "-t", help = "Record types to query"),
    ] = "A,AAAA,MX,NS",
    db: Annotated[
        Path,
        typer.Option("--db", help = "Passive DNS database path"),
    ] = Path("passive_dns.db"),
    server: Annotated[
        str | None,
        typer.Option("--server", "-s", help = "DNS server to use"),
    ] = None,
) -> None:
    """
    Query a domain and store its records in the passive DNS database.
    """
    record_types = parse_record_types(record_type)
    result = asyncio.run(lookup(domain, record_types, server))
    store = PassiveDNSStore(str(db))
    stored = store.record_result(result)
    store.close()
    console.print(
        f"[green]:heavy_check_mark:[/green] Stored [bold]{stored}[/bold] "
        f"record(s) for {domain} in {db}"
    )


@passive_app.command("history")
def passive_history(
    domain: Annotated[str,
                      typer.Argument(help = "Domain to look up history for")],
    db: Annotated[
        Path,
        typer.Option("--db", help = "Passive DNS database path"),
    ] = Path("passive_dns.db"),
) -> None:
    """
    Show the stored resolution history for a domain.
    """
    store = PassiveDNSStore(str(db))
    records = store.history(domain)
    store.close()
    print_passive_records(records, f"History: {domain}")


@passive_app.command("resolutions")
def passive_resolutions(
    value: Annotated[str,
                     typer.Argument(help = "Value/IP to find domains for")],
    db: Annotated[
        Path,
        typer.Option("--db", help = "Passive DNS database path"),
    ] = Path("passive_dns.db"),
) -> None:
    """
    Show every domain that has resolved to a given value (e.g. an IP).
    """
    store = PassiveDNSStore(str(db))
    records = store.resolutions(value)
    store.close()
    print_passive_records(records, f"Resolutions: {value}")


if __name__ == "__main__":
    app()
