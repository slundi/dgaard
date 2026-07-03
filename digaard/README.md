# digaard

A modern DNS query CLI — `dig` done right.

Modelled on [`natesales/q`](https://github.com/natesales/q). Written in Rust,
one workspace member of the [dgaard](https://codeberg.org/slundi/dgaard) proxy
project, but shippable as a standalone binary.

## Quickstart

```sh
# Ask 1.1.1.1 for example.com's A record
digaard example.com @1.1.1.1

# Multiple domains, JSON on stdout, latency summary on stderr
digaard example.com google.com github.com --json --stats

# Batch from a file (or stdin) with 16-way fan-out
cat domains.txt | digaard -f - -j 16 --json

# DoH POST (default)
digaard example.com --https @cloudflare-dns.com

# DoH GET
digaard example.com --https @cloudflare-dns.com --doh-method GET

# DoT with ALPN "dot"
digaard example.com --tls @dns.google

# DoQ (RFC 9250)
digaard example.com --quic @dns.adguard.com

# Race two servers, return the fastest answer
digaard -s 1.1.1.1 -s 9.9.9.9 --server-strategy race example.com

# Reverse lookup (IPv4 / IPv6)
digaard -x 8.8.8.8
digaard -x 2001:4860:4860::8888

# Internationalised domain names
digaard bücher.de           # sent as xn--bcher-kva.de, Unicode form shown

# DNSSEC record display + upstream-validated verdict
digaard cloudflare.com --dnssec --https @cloudflare-dns.com
digaard cloudflare.com --validate --https @cloudflare-dns.com

# EDNS options: ECS, NSID, DNS cookie, RFC 7830 padding
digaard example.com --subnet 192.0.2.0/24 --nsid --cookie --pad

# Raw wire dump (for debugging)
digaard example.com --hex

# +dig-style shortcuts still work
digaard example.com +short +dnssec
```

## Comparison to dig and q

| Feature                         | `dig` | `q`  | `digaard` |
| ------------------------------- | :---: | :--: | :-------: |
| UDP / TCP (Do53)                |  Yes  | Yes  |    Yes    |
| DoT (RFC 7858)                  |  No   | Yes  |    Yes    |
| DoH (RFC 8484), POST + GET      |  No   | Yes  |    Yes    |
| DoQ (RFC 9250)                  |  No   | Yes  |    Yes    |
| DNSSEC records                  |  Yes  | Yes  |    Yes    |
| DNSSEC verdict (AD-based)       |  No   | Some |    Yes    |
| Reverse (`-x IP`)               |  Yes  | Yes  |    Yes    |
| IDN / punycode auto-conversion  | Some  | Yes  |    Yes    |
| EDNS Client Subnet              |  No   | Yes  |    Yes    |
| EDNS NSID / Cookie / Padding    | Some  | Yes  |    Yes    |
| Multiple domains per invocation |  No   | Yes  |    Yes    |
| Stdin / file batch input        |  No   |  No  |    Yes    |
| Bounded-concurrency fan-out     |  No   |  No  |    Yes    |
| JSON output (NDJSON in batch)   |  No   | Yes  |    Yes    |
| Latency summary (min/p50/p95)   |  No   |  No  |    Yes    |
| TOML config file                |  No   |  No  |    Yes    |
| `+dig` shortcuts                |  Yes  |  No  |    Yes    |

## Cookbook

### One domain, custom resolver

```sh
digaard example.com @1.1.1.1
digaard example.com -s 1.1.1.1 -p 5353    # non-standard port
```

### Force a transport

```sh
digaard example.com --udp    # default
digaard example.com --tcp
digaard example.com --tls    @dns.google
digaard example.com --https  @cloudflare-dns.com
digaard example.com --quic   @dns.adguard.com
```

### DoH GET / custom path

```sh
digaard example.com --https @cloudflare-dns.com --doh-method GET --doh-path /dns-query
```

### TLS with self-signed cert (debug)

```sh
digaard example.com --tls @dot.example --tls-insecure --tls-servername dot.example
digaard example.com --tls @dot.example --tls-ca /etc/ssl/local-root.pem
```

### Multiple resolvers

```sh
# First one wins
digaard -s 1.1.1.1 -s 9.9.9.9 example.com

# Race — return whoever answers first
digaard -s 1.1.1.1 -s 9.9.9.9 --server-strategy race example.com

# Distribute batch across resolvers
digaard -s 1.1.1.1 -s 9.9.9.9 --server-strategy round-robin \
        -f domains.txt -j 16
```

### Batch input

```sh
digaard a.com b.com c.com                     # positional
digaard -f domains.txt                        # from file
cat domains.txt | digaard -f -                # from stdin
digaard -f - --json --stats -j 32 < domains.txt
```

### EDNS(0) options

```sh
digaard example.com --subnet 203.0.113.0/24   # ECS (RFC 7871)
digaard example.com --nsid                    # NSID (RFC 5001)
digaard example.com --cookie                  # random client cookie
digaard example.com --cookie-hex deadbeefcafebabe
digaard example.com --pad                     # 128-byte block padding
digaard example.com --pad-size 468            # custom block size
digaard example.com --no-edns                 # disable OPT altogether
```

### DNSSEC

```sh
digaard cloudflare.com -t DNSKEY               # show DNSKEY records
digaard cloudflare.com --dnssec                # set DO bit; show RRSIGs
digaard cloudflare.com --validate --https @cloudflare-dns.com
digaard example.com    --validate --trust-anchor /var/lib/unbound/root.key
```

### Debugging

```sh
digaard example.com --hex                     # raw response wire bytes
digaard example.com --edge                    # decode Extended DNS Errors
digaard example.com -vv                       # verbose logging
```

### Config file

Path: `--config PATH`, else `$XDG_CONFIG_HOME/digaard/config.toml`,
else `~/.config/digaard/config.toml`.

```toml
default_server = "https://dns.quad9.net/dns-query"
default_transport = "https" # udp | tcp | tls | https | quic
default_format = "pretty" # pretty | text | json
color = "auto" # auto | always | never
timeout_ms = 3000
retry = 2
concurrency = 16

# or a list for multi-server strategies:
# default_servers = ["1.1.1.1", "9.9.9.9"]
```

CLI flags always override config values.

### `+dig` shortcuts

For muscle memory:

| Shortcut  | Canonical flag |
| --------- | -------------- |
| `+short`  | `--short`      |
| `+dnssec` | `--dnssec`     |
| `+tcp`    | `--tcp`        |
| `+nord`   | `--no-rd`      |
| `+adflag` | `--ad`         |
| `+cdflag` | `--cd`         |

`+trace` is not (yet) implemented.

## Output formats

- **Text** (default): dig-style HEADER / QUESTION / ANSWER / AUTHORITY /
  ADDITIONAL sections. Colored via `--color auto`.
- **JSON** (`--json`): NDJSON — one JSON object per response, one per line
  when batching. Suitable for `jq`.
- **Short** (`--short` / `+short`): only the RDATA field of each answer, one
  per line.
- **Hex** (`--hex`): xxd-style dump of the response wire bytes.

## Building

```sh
cargo build --release -p digaard
```

The binary lands at `target/release/digaard`. It has no OpenWrt-specific
optimisations — the `[profile.release]` overrides in the workspace root make
this a developer tool with useful backtraces and normal opt levels.

## License

GPL-3.0 — see `LICENCE.md` at the workspace root.

## See also

- [`docs/Roadmap-digaard.md`](../docs/Roadmap-digaard.md) — design goals and milestone plan
- [`docs/CLI-digaard.md`](../docs/CLI-digaard.md) — exhaustive flag reference
- [`docs/digaard.1`](../docs/digaard.1) — man page
