```ruby
██████╗ ███╗   ██╗███████╗██╗      ██████╗  ██████╗ ██╗  ██╗██╗   ██╗██████╗
██╔══██╗████╗  ██║██╔════╝██║     ██╔═══██╗██╔═══██╗██║ ██╔╝██║   ██║██╔══██╗
██║  ██║██╔██╗ ██║███████╗██║     ██║   ██║██║   ██║█████╔╝ ██║   ██║██████╔╝
██║  ██║██║╚██╗██║╚════██║██║     ██║   ██║██║   ██║██╔═██╗ ██║   ██║██╔═══╝
██████╔╝██║ ╚████║███████║███████╗╚██████╔╝╚██████╔╝██║  ██╗╚██████╔╝██║
╚═════╝ ╚═╝  ╚═══╝╚══════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝
```

> Professional DNS query CLI with Rich terminal output, reverse lookups, and WHOIS integration.

## What It Does

- Query A, AAAA, MX, NS, TXT, CNAME, and SOA records with colored table output
- Reverse DNS lookup to resolve IP addresses back to hostnames
- Trace DNS resolution path from root servers to authoritative nameservers
- Batch lookups with concurrent queries for processing domain lists
- WHOIS integration for domain registration information
- JSON export for scripting and pipeline integration

## Quick Start

```bash
uv tool install dnslookup-cli
dnslookup query example.com
```

> [!TIP]
> This project uses [`just`](https://github.com/casey/just) as a command runner. Type `just` to see all available commands.
>
> Install: `curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`

## Commands

| Command | Description |
|---------|-------------|
| `dnslookup query` | Query DNS records for a domain with colored table output |
| `dnslookup reverse` | Resolve an IP address back to its hostname |
| `dnslookup trace` | Trace the DNS resolution path from root to authoritative servers |
| `dnslookup batch` | Query multiple domains concurrently from a file |
| `dnslookup whois` | Retrieve WHOIS registration information for a domain |
