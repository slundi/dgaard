# `digaard` CLI reference

Exhaustive list of every flag `digaard` accepts. Match `digaard --help` for
truth-in-code; this file is hand-maintained but kept in sync at each release.

## Synopsis

```text
digaard [OPTIONS] <NAME>...
digaard [OPTIONS] -f <FILE>
digaard [OPTIONS] -x <IP>
```

## Positional arguments

| Positional  | Description                                                                                                                          |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `<NAME>...` | One or more domain names. IDN input is punycode-encoded before wire send. Repeatable. Ignored when `-x` interprets the arg as an IP. |

## Query shape

| Flag                  | Description                                                                                                                                                                                       |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-t`, `--type=TYPE`   | Record type. Accepts any hickory-proto-known type: `A`, `AAAA`, `MX`, `TXT`, `CNAME`, `NS`, `SOA`, `PTR`, `SRV`, `CAA`, `HTTPS`, `SVCB`, `DNSKEY`, `DS`, `RRSIG`, `NSEC3`, `ANY`, …. Default `A`. |
| `-c`, `--class=CLASS` | DNS class: `IN` (default), `CH`, `HS`, `ANY`.                                                                                                                                                     |
| `-x`, `--reverse`     | Interpret positional args as IPv4/IPv6 addresses and synthesise the `in-addr.arpa` / `ip6.arpa` PTR question.                                                                                     |
| `--aa`                | Set the AA (Authoritative Answer) bit on the outgoing query.                                                                                                                                      |
| `--ad`                | Set the AD (Authentic Data) bit.                                                                                                                                                                  |
| `--cd`                | Set the CD (Checking Disabled) bit.                                                                                                                                                               |
| `--no-rd`             | Clear the Recursion Desired bit. Default: RD set.                                                                                                                                                 |
| `--dnssec`            | Set the EDNS DO (DNSSEC OK) bit. Enables EDNS(0).                                                                                                                                                 |

## Transport

| Flag                     | Description                                                                                      |
| ------------------------ | ------------------------------------------------------------------------------------------------ |
| `-s`, `--server=SERVER`  | Nameserver address (IP or hostname). Repeatable. Bare `@server` also supported anywhere in argv. |
| `--server-strategy=MODE` | With multiple `-s`: `first` (default), `race`, `round-robin`.                                    |
| `-p`, `--port=PORT`      | Override the default port for the chosen transport.                                              |
| `--udp`                  | Force UDP (default).                                                                             |
| `--tcp`                  | Force TCP.                                                                                       |
| `--tls`                  | DoT (RFC 7858). Port 853. ALPN `dot`.                                                            |
| `--https`                | DoH (RFC 8484). Port 443.                                                                        |
| `--quic`                 | DoQ (RFC 9250). Port 853. ALPN `doq`.                                                            |
| `-4`                     | Bind the outbound socket to IPv4 only.                                                           |
| `-6`                     | Bind the outbound socket to IPv6 only.                                                           |
| `--timeout=MS`           | Per-query timeout in ms. Default 5000.                                                           |
| `--retry=N`              | Number of retries on UDP timeout. Default 2.                                                     |

### TLS / DoT / DoH shared options

| Flag                    | Description                                                            |
| ----------------------- | ---------------------------------------------------------------------- |
| `--tls-servername=NAME` | Override SNI / expected certificate name. Defaults to the server host. |
| `--tls-insecure`        | Skip TLS certificate verification. Debug only; emits a stderr warning. |
| `--tls-ca=FILE`         | PEM file of additional trust roots. Repeatable.                        |

### DoH-only options

| Flag              | Description                                               |
| ----------------- | --------------------------------------------------------- |
| `--doh-method=M`  | `POST` (default) or `GET`. `GET` uses base64url `?dns=…`. |
| `--doh-path=PATH` | URL path. Default `/dns-query`.                           |

## EDNS(0)

| Flag                   | Description                                                                    |
| ---------------------- | ------------------------------------------------------------------------------ |
| `--edns` / `--no-edns` | Enable / disable OPT record. Default enabled.                                  |
| `--edns-bufsize=BYTES` | Advertised UDP payload size in OPT. Default 1232.                              |
| `--subnet=PREFIX`      | EDNS Client Subnet (RFC 7871). Example: `192.0.2.0/24` or `2001:db8::/32`.     |
| `--nsid`               | Request NSID (RFC 5001).                                                       |
| `--cookie`             | Send a random 8-byte DNS Cookie (RFC 7873).                                    |
| `--cookie-hex=HEX`     | Send a DNS Cookie with an explicit hex value.                                  |
| `--pad`                | Enable EDNS Padding (RFC 7830), rounding wire size to a multiple of 128 bytes. |
| `--pad-size=SIZE`      | Custom padding block size.                                                     |
| `--edge`               | Decode Extended DNS Errors (RFC 8914) into the pretty ADDITIONAL block.        |

## DNSSEC

| Flag                  | Description                                                         |
| --------------------- | ------------------------------------------------------------------- |
| `--validate`          | Classify response as SECURE / INSECURE / BOGUS. Implies `--dnssec`. |
| `--trust-anchor=FILE` | BIND-style trust-anchor file (DNSKEY records). Repeatable.          |

Validator rules (in order):

1. `SERVFAIL` → BOGUS.
2. Response AD bit set → SECURE (trust upstream validator).
3. RRSIG covers the answer _and_ a DNSKEY (in response or trust anchor) verifies → SECURE.
4. RRSIG present but nothing verifies → BOGUS.
5. No RRSIG → INSECURE.

Full recursive chain-of-trust construction is not implemented (deferred).

## Batch / scripting

| Flag                    | Description                                                                              |
| ----------------------- | ---------------------------------------------------------------------------------------- |
| `-f`, `--file=PATH`     | Read domains from file, one per line. `-` = stdin. Blank lines and `#` comments ignored. |
| `-j`, `--concurrency=N` | Max concurrent in-flight queries. Default `min(cpus, 32)`.                               |
| `--stats`               | Emit per-response `Query time` + end-of-run min/avg/p50/p95/max & error rate on stderr.  |

## Output

| Flag            | Description                                |
| --------------- | ------------------------------------------ |
| `--text`        | Dig-style text (default).                  |
| `--json`        | NDJSON. One object per response.           |
| `-q`, `--short` | Print only RDATA, one per line.            |
| `--color=WHEN`  | `auto` (default), `always`, `never`.       |
| `--hex`         | xxd-style hex dump of response wire bytes. |

## Meta

| Flag              | Description                                                                   |
| ----------------- | ----------------------------------------------------------------------------- |
| `-v`, `--verbose` | Increase logging verbosity. Repeatable: `-v` info, `-vv` debug, `-vvv` trace. |
| `--config=FILE`   | Load defaults from a TOML file. See "Config file" below.                      |
| `-h`, `--help`    | Print help and exit.                                                          |
| `-V`, `--version` | Print version and exit.                                                       |

## `+dig-style` shortcuts

Rewritten in an argv pre-pass before bpaf sees them:

| Shortcut  | Canonical flag |
| --------- | -------------- |
| `+short`  | `--short`      |
| `+dnssec` | `--dnssec`     |
| `+tcp`    | `--tcp`        |
| `+nord`   | `--no-rd`      |
| `+adflag` | `--ad`         |
| `+cdflag` | `--cd`         |

## Config file

Path resolution: explicit `--config PATH` >
`$XDG_CONFIG_HOME/digaard/config.toml` > `~/.config/digaard/config.toml`.
Missing files are ignored (no error) unless `--config` was explicit.

Fields (all optional; CLI flags override):

```toml
default_server = "https://dns.quad9.net/dns-query"
# or
# default_servers = ["1.1.1.1", "9.9.9.9"]
default_transport = "udp" # udp | tcp | tls | https | quic
default_format = "pretty" # pretty | text | json
color = "auto" # auto | always | never
timeout_ms = 3000
retry = 2
concurrency = 16
```

## Exit codes

- `0` — success.
- `1` — one or more queries returned an error (timeout, transport failure,
  invalid name, etc.). First error is printed to stderr; NDJSON output for
  successful queries still lands on stdout.
- `2` — argument parsing failure (unknown flag, bad `--config`, invalid TOML).
