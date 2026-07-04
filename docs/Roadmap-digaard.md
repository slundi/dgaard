# `digaard` — CLI DNS Query Tool — Design & Roadmap

A `dig`-style command-line DNS client, modelled on [natesales/q](https://github.com/natesales/q), living as a new member of the `dgaard` Cargo workspace.

## Goals

- Provide a **modern, ergonomic, multi-transport DNS query tool** — a pure client, independent of the `dgaard` proxy runtime.
- Match the transport surface of `q`: **Do53 (UDP+TCP), DoT, DoH, DoQ**.
- Match the introspection surface of `dig`: **full header/flag control, EDNS(0) options, DNSSEC records, reverse lookups, IDN**.
- First-class **scripting ergonomics**: multiple domains per invocation, stdin/file input, bounded-concurrency fan-out, latency statistics.
- Multiple **output renderers**: dig-compatible pretty-print, JSON (line-delimited for batches), short/raw values, colored TTY output.
- Idiomatic Rust: `bpaf` for CLI parsing, `hickory-proto` at the wire layer, `tokio` for concurrency.

## Non-goals (for this roadmap)

- No integration with the local `dgaard-daemon` (no Unix-socket introspection, no filter-decision explanation). `digaard` is a **pure client** — it MAY be pointed at `127.0.0.1:53` like any other resolver, nothing more.
- No caching, no resolver logic (retry-with-fallback, EDNS-fallback, CNAME chase beyond what the wire response contains). `digaard` sends one query, prints one response.
- No zone-transfer (`AXFR`/`IXFR`) in the first release — added as a follow-up if requested.
- No DoH server / DoT server mode. Client only.
- No update / dynamic DNS (`nsupdate`-style RFC 2136 UPDATE messages).

---

## Feature comparison

| Feature                          | `dig` | `q`  | `digaard` |
| -------------------------------- | :---: | :--: | :-------: |
| UDP / TCP (Do53)                 |  Yes  | Yes  |    Yes    |
| DoT (RFC 7858)                   |  No   | Yes  |    Yes    |
| DoH (RFC 8484)                   |  No   | Yes  |    Yes    |
| DoQ (RFC 9250)                   |  No   | Yes  |    Yes    |
| DNSSEC records (RRSIG/DS/NSEC)   |  Yes  | Yes  |    Yes    |
| DNSSEC chain-of-trust validation |  No   | Some |    Yes    |
| Reverse (`-x IP`)                |  Yes  | Yes  |    Yes    |
| IDN / punycode auto-conversion   | Some  | Yes  |    Yes    |
| EDNS Client-Subnet (RFC 7871)    |  No   | Yes  |    Yes    |
| EDNS NSID (RFC 5001)             |  Yes  | Yes  |    Yes    |
| EDNS Padding (RFC 7830)          |  No   | Yes  |    Yes    |
| DNS Cookies (RFC 7873)           |  Yes  | Yes  |    Yes    |
| Multiple domains per invocation  |  No   | Yes  |    Yes    |
| Stdin / file batch input         |  No   |  No  |    Yes    |
| Bounded-concurrency fan-out      |  No   |  No  |    Yes    |
| JSON output                      |  No   | Yes  |    Yes    |
| Latency summary (min/p50/p95)    |  No   |  No  |    Yes    |

---

## Positioning in the workspace

`digaard` is treated as a **developer / desktop tool**, not an OpenWrt payload.

- New workspace member: `digaard/` at the repo root, listed in the root `Cargo.toml` `[workspace.members]`.
- Its `[profile.release]` **overrides** the workspace default: no `opt-level = "z"`, no `panic = "abort"`. Prioritises runtime speed and useful backtraces over binary size.
- Not shipped in the `package/` OpenWrt output. Not built by default in cross-compilation targets.
- Depends only on `hickory-proto` (new to workspace) and existing workspace deps (`tokio`, `thiserror`, `rustls`, `hyper*`, `url`, `env_logger`, `log`, `serde`, `serde_json`).

---

## CLI surface (bpaf)

Design principle: **positional-first for the common case** — `digaard example.com` should Just Work. Flags mirror `q`'s spelling where reasonable; `+dig-style` shortcuts are supported as aliases.

### Synopsis

```text
digaard [OPTIONS] <DOMAIN>...
digaard [OPTIONS] -f <FILE>
digaard [OPTIONS] -x <IP>
```

### Positional arguments

- `<DOMAIN>...` — one or more domains (or IPs, if `-x` is set). IDN input accepted; converted to A-labels before wire encoding. When multiple positional args are given, each is queried independently and results are grouped.

### Query shape

| Flag                  | Description                                                                                                                             |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `-t, --type <RRTYPE>` | Record type (`A`, `AAAA`, `MX`, `TXT`, `CNAME`, `NS`, `SOA`, `PTR`, `SRV`, `CAA`, `HTTPS`, `SVCB`, `ANY`, …). Repeatable. Default: `A`. |
| `-c, --class <CLASS>` | DNS class (`IN`, `CH`, `HS`). Default: `IN`.                                                                                            |
| `-x, --reverse`       | Interpret each positional argument as an IPv4/IPv6 address and query the corresponding `in-addr.arpa` / `ip6.arpa` PTR.                 |
| `--aa`                | Set the AA (authoritative-answer) bit on the outgoing query.                                                                            |
| `--ad`                | Set the AD (authentic-data) bit.                                                                                                        |
| `--cd`                | Set the CD (checking-disabled) bit.                                                                                                     |
| `--rd / --no-rd`      | Recursion Desired. Default: `--rd`.                                                                                                     |
| `--do`                | EDNS DO (DNSSEC OK) bit. Implied by `--dnssec`.                                                                                         |
| `--id <N>`            | Force a specific 16-bit query ID (default: random).                                                                                     |

### Transport

| Flag                      | Description                                                                                                                                                                                                                   |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-s, --server <ENDPOINT>` | Resolver endpoint. Scheme selects transport: `udp://`, `tcp://`, `tls://`, `https://`, `quic://`. Bare `1.1.1.1` defaults to UDP. Bare `https://…` is DoH. Repeatable — the tool races or falls back per `--server-strategy`. |
| `--server-strategy <S>`   | `first` (default), `race`, `round-robin` when multiple `-s` are given.                                                                                                                                                        |
| `-p, --port <PORT>`       | Override the default port for the chosen transport.                                                                                                                                                                           |
| `--udp`                   | Force UDP (shortcut for `udp://<server>`).                                                                                                                                                                                    |
| `--tcp`                   | Force TCP.                                                                                                                                                                                                                    |
| `--tls`                   | Force DoT (default port 853).                                                                                                                                                                                                 |
| `--https`                 | Force DoH (default port 443, `POST`).                                                                                                                                                                                         |
| `--quic`                  | Force DoQ (default port 853).                                                                                                                                                                                                 |
| `--doh-method <M>`        | `GET` or `POST` (default: `POST`).                                                                                                                                                                                            |
| `--doh-path <PATH>`       | DoH URL path (default: `/dns-query`).                                                                                                                                                                                         |
| `--tls-servername <N>`    | SNI override for DoT/DoH/DoQ.                                                                                                                                                                                                 |
| `--tls-insecure`          | Skip certificate verification (developer aid; loud warning on stderr).                                                                                                                                                        |
| `--tls-ca <FILE>`         | Additional trust root(s) (PEM).                                                                                                                                                                                               |
| `--alpn <PROTO>`          | Force ALPN token (`dot`, `doq`, `h2`).                                                                                                                                                                                        |
| `-4, --ipv4-only`         | Only use IPv4 to reach the resolver.                                                                                                                                                                                          |
| `-6, --ipv6-only`         | Only use IPv6 to reach the resolver.                                                                                                                                                                                          |
| `--source <ADDR>`         | Bind local socket to a specific source address.                                                                                                                                                                               |
| `--timeout <MS>`          | Per-query timeout (default: 5000).                                                                                                                                                                                            |
| `--retry <N>`             | Number of retries on timeout (default: 2; UDP only).                                                                                                                                                                          |

### EDNS(0)

| Flag                     | Description                                                                         |
| ------------------------ | ----------------------------------------------------------------------------------- |
| `--edns / --no-edns`     | Enable/disable EDNS(0) OPT record. Default: `--edns`.                               |
| `--edns-bufsize <BYTES>` | UDP payload size advertised in OPT (default: 1232).                                 |
| `--subnet <PREFIX>`      | EDNS Client-Subnet (`1.2.3.0/24` or `::/0`).                                        |
| `--nsid`                 | Request NSID.                                                                       |
| `--cookie [HEX]`         | Send DNS Cookie. Value optional (random 8-byte client cookie generated if omitted). |
| `--pad [SIZE]`           | EDNS Padding (RFC 7830). Default block size: 128.                                   |
| `--edge`                 | Print Extended DNS Errors (RFC 8914) when present.                                  |

### DNSSEC

| Flag                    | Description                                                                                                     |
| ----------------------- | --------------------------------------------------------------------------------------------------------------- |
| `--dnssec`              | Shortcut: sets `--do`, prints RRSIG/NSEC/DS records.                                                            |
| `--validate`            | Perform full chain-of-trust validation from configured trust anchor(s). Prints `SECURE` / `INSECURE` / `BOGUS`. |
| `--trust-anchor <FILE>` | Additional trust-anchor file (BIND DS/DNSKEY format). Root KSK compiled in as default.                          |

### Batch / scripting

| Flag                    | Description                                                                              |
| ----------------------- | ---------------------------------------------------------------------------------------- |
| `-f, --file <PATH>`     | Read domains from file, one per line. `-` = stdin. Blank lines and `#` comments ignored. |
| `-j, --concurrency <N>` | Max concurrent in-flight queries (default: `min(cpus, 32)`).                             |
| `--stats`               | Emit per-query latency and end-of-run summary (min/avg/p50/p95/max, error rate).         |

### Output

| Flag              | Description                                                               |
| ----------------- | ------------------------------------------------------------------------- |
| `--format <FMT>`  | `pretty` (default), `json`, `short`.                                      |
| `--color <WHEN>`  | `auto` (default), `always`, `never`. `auto` = TTY detection.              |
| `--no-header`     | Suppress the `;; ->>HEADER<<-` line in pretty output.                     |
| `--no-question`   | Suppress the QUESTION section.                                            |
| `--no-additional` | Suppress the ADDITIONAL section.                                          |
| `--show-query`    | Also print the outgoing query on stderr (like `dig +qr`).                 |
| `--hex`           | Print raw wire bytes (hex-dump) instead of parsed records. Debugging aid. |

### Meta

| Flag               | Description                                                              |
| ------------------ | ------------------------------------------------------------------------ |
| `-v, --verbose`    | Increase logging verbosity (repeatable: `-vv`, `-vvv`).                  |
| `-q, --quiet`      | Suppress non-answer output.                                              |
| `--config <FILE>`  | Alternate config path (default: `$XDG_CONFIG_HOME/digaard/config.toml`). |
| `--help` / `-h`    | Help.                                                                    |
| `--version` / `-V` | Version + build info (git SHA, feature flags).                           |

### `+dig-style` shortcuts (aliases)

For muscle-memory:

- `+short` → `--format short`
- `+dnssec` → `--dnssec`
- `+trace` → planned for M6 (iterative trace from root; not in initial scope)
- `+tcp` → `--tcp`
- `+nord` → `--no-rd`
- `+adflag` → `--ad`
- `+cdflag` → `--cd`

Parsed by a small pre-pass over `argv` that rewrites `+foo` to the canonical flag before handing off to `bpaf`.

### Config file (optional)

`$XDG_CONFIG_HOME/digaard/config.toml` — sets defaults for `--server`, `--timeout`, `--format`, `--color`, `--concurrency`. CLI flags always override. Same `toml-span` parser used elsewhere in the workspace, for consistency.

Example:

```toml
default_server = "https://dns.quad9.net/dns-query"
default_format = "pretty"
timeout_ms = 3000
concurrency = 16
```

---

## Architecture

```
digaard/
├── Cargo.toml
├── README.md
├── src/
│   ├── main.rs          # bpaf entry point, tokio runtime, dispatch
│   ├── cli.rs           # bpaf parser, +shortcut prepass, config merge
│   ├── config.rs        # toml-span config loader
│   ├── query/
│   │   ├── mod.rs       # QueryPlan (target, type, class, EDNS, flags)
│   │   ├── build.rs     # DnsPacket construction via hickory-proto
│   │   └── batch.rs     # Fan-out orchestrator (bounded concurrency)
│   ├── transport/
│   │   ├── mod.rs       # trait Transport { async fn exchange(...) }
│   │   ├── udp.rs
│   │   ├── tcp.rs
│   │   ├── dot.rs       # rustls on top of tokio TCP
│   │   ├── doh.rs       # hyper + hyper-rustls (workspace-shared)
│   │   └── doq.rs       # quinn (new dep)
│   ├── idn.rs           # Unicode → A-label conversion (idna crate)
│   ├── dnssec/
│   │   ├── mod.rs
│   │   └── validate.rs  # Trust-anchor loader + chain validation
│   ├── output/
│   │   ├── mod.rs       # enum Renderer { Pretty, Json, Short }
│   │   ├── pretty.rs    # dig-compatible sections
│   │   ├── json.rs      # serde_json line-delimited
│   │   ├── short.rs
│   │   └── color.rs     # ANSI palette + TTY detection
│   └── stats.rs         # Latency histogram, summary printing
└── tests/
    ├── cli_smoke.rs           # bpaf parse tests
    ├── udp_roundtrip.rs       # Local test server
    ├── doh_roundtrip.rs
    ├── idn.rs
    ├── reverse.rs
    ├── dnssec_records.rs
    └── batch_stdin.rs
```

Key trait:

```rust
#[async_trait::async_trait]
pub trait Transport: Send + Sync {
    async fn exchange(&self, query: &[u8]) -> Result<Vec<u8>, TransportError>;
}
```

One `Transport` instance is constructed from the `--server` spec and reused across all queries in a batch. Instance lifetime spans the whole invocation, so DoT/DoH/DoQ connections are established once and reused (equivalent to `q`'s connection-reuse behaviour).

---

## New dependencies (workspace-level)

Added to `[workspace.dependencies]` in the root `Cargo.toml`:

```toml
# Low-level DNS wire encoding/decoding
hickory-proto = "0.26" # matches existing hickory-resolver major

# QUIC transport for DoQ
quinn = { version = "0.11", default-features = false, features = ["rustls", "runtime-tokio"] }

# IDN handling
idna = "1"

# CLI parsing (per project convention)
bpaf = { version = "0.9", features = ["derive"] }

# TTY detection for --color auto
is-terminal = "0.4"
```

Reused from existing workspace deps: `tokio`, `thiserror`, `rustls`, `hyper`, `hyper-rustls`, `hyper-util`, `http-body-util`, `url`, `env_logger`, `log`, `serde`, `serde_json`, `async-trait`, `getrandom`.

The `digaard` crate does **not** depend on `dgaard-engine`, `dgaard-daemon`, or any other `dgaard-*` workspace member. It is a leaf tool.

---

## Milestones

Each milestone ends with a green `cargo nextest run`, zero `cargo clippy -- -D warnings`, and a conventional commit.

### M1 — Skeleton & UDP (target: ~1 week)

**Deliverable**: `digaard example.com` returns an `A` record from `1.1.1.1:53` via UDP with dig-style output.

- Create `digaard/` workspace crate.
- `bpaf` CLI parser covering the minimal flag set: `-t`, `-c`, `-s`, `-p`, `--udp`, `--timeout`, `--rd/--no-rd`, `-v`, `-V`, `-h`.
- `Transport` trait + `UdpTransport` impl (socket bind, retry-on-timeout).
- Query construction via `hickory-proto::op::Message`.
- Pretty-print renderer (no color yet): HEADER, QUESTION, ANSWER, AUTHORITY, ADDITIONAL sections.
- Basic integration test: local mock UDP server responds with a fixed answer.
- Suggested commit: `feat(digaard): initial UDP client with dig-style output`.

### M2 — TCP, batch mode, output formats (~1 week)

- `TcpTransport` (2-byte length prefix per RFC 1035).
- Fallback: when a UDP response has TC=1 and `--retry` allows, transparently re-issue over TCP.
- Positional multi-domain support: `digaard a.com b.com c.com`.
- `-f/--file` and `-f -` (stdin) input.
- `-j/--concurrency` bounded-fan-out via `tokio::sync::Semaphore`.
- JSON renderer (line-delimited when batching, single object when single query).
- Short renderer (`+short` equivalent).
- `--color auto/always/never` with palette in `output/color.rs`.
- Suggested commit: `feat(digaard): TCP transport, batch mode, JSON/short renderers`.

### M3 — EDNS, reverse, IDN (~1 week)

- Full EDNS(0) OPT construction: `--edns-bufsize`, `--subnet`, `--nsid`, `--cookie`, `--pad`.
- `-x/--reverse` with IPv4 and IPv6 argument detection.
- IDN input: `xn--` output via `idna` crate; also print Unicode form in pretty output.
- Extended DNS Errors decoding (`--edge`) in the ADDITIONAL section.
- `--hex` wire-dump output for debugging.
- Suggested commit: `feat(digaard): EDNS options, reverse queries, IDN handling`.

### M4 — DoT and DoH (~1-2 weeks)

- `DotTransport`: `tokio-rustls` on top of `TcpStream`, ALPN `dot`, connection pooling within a single invocation.
- `DohTransport`: `hyper` + `hyper-rustls` (already in workspace), `POST` and `GET` methods, custom `--doh-path`, SNI override.
- `--tls-servername`, `--tls-insecure`, `--tls-ca` plumbed through both.
- `--server-strategy first|race|round-robin` when multiple `-s` flags are given.
- Suggested commit: `feat(digaard): DoT and DoH transports`.

### M5 — DoQ (~1 week)

- Add `quinn` dependency (workspace-level).
- `DoqTransport`: RFC 9250 semantics (one stream per query, ALPN `doq`), connection reuse across batch queries.
- Suggested commit: `feat(digaard): DoQ transport (RFC 9250)`.

### M6 — DNSSEC validation & stats (~1-2 weeks)

- Record display for RRSIG, DNSKEY, DS, NSEC, NSEC3, CDNSKEY, CDS in pretty and JSON renderers.
- `--validate`: full chain-of-trust from a compiled-in root KSK anchor, following DS/DNSKEY delegations. Print `SECURE` / `INSECURE` / `BOGUS` with reason.
- `--trust-anchor` loader (BIND DS/DNSKEY text format).
- `--stats`: per-query latency, end-of-run summary (min/avg/p50/p95/max, error rate).
- Suggested commit: `feat(digaard): DNSSEC chain validation and latency stats`.

### M7 — Polish, docs, packaging (~0.5-1 week)

- `--config` file support with `toml-span`.
- `+dig-style` shortcut pre-pass.
- Man page generated from `bpaf` metadata (via `bpaf-doc` or hand-written `.1` in `docs/`).
- Shell completions (bash, zsh, fish) via `bpaf`'s completion generation.
- README with 20-line quickstart, CLI cookbook, comparison table.
- `docs/CLI-digaard.md` — full flag reference.
- Suggested commit: `docs(digaard): manpage, completions, and CLI reference`.

---

## Testing strategy

- **Unit tests** in each module: EDNS-option encoding, IDN edge cases (empty label, mixed script), reverse-address formatting, latency histogram accuracy, `+shortcut` argv rewriting.
- **Integration tests** in `digaard/tests/`, one file per transport:
  - `udp_roundtrip.rs` — spawn a local `tokio::net::UdpSocket` mock server, assert wire format sent and response parsed.
  - `tcp_roundtrip.rs` — same shape, plus TC=1 fallback simulation.
  - `dot_roundtrip.rs` — tokio-rustls test server with self-signed cert; `--tls-insecure` path.
  - `doh_roundtrip.rs` — axum test server responding to `/dns-query`.
  - `doq_roundtrip.rs` — quinn test server (gated behind `#[cfg(feature = "doq-tests")]` if MSRV pain).
  - `dnssec_validate.rs` — canned zones with known signatures (borrow test vectors from hickory).
  - `batch_stdin.rs` — pipe 100 domains via stdin, assert output ordering and concurrency cap.
- **Snapshot tests** (`insta` or hand-rolled) for pretty-print output on a set of known responses. Guards against accidental format regression.
- **Fuzz target** (optional, gated): `cargo fuzz` on the response parser using `hickory-proto` — mostly redundant with upstream's fuzzing, but catches integration bugs.
- No live-network tests in CI (deterministic, no external dependency).

Run command: `cargo nextest run -p digaard`.

---

## Documentation deliverables

- `digaard/README.md` — quickstart, common recipes, comparison to `dig` / `q`.
- `docs/Roadmap-digaard.md` — this file.
- `docs/CLI-digaard.md` — exhaustive flag reference generated from source of truth (either `bpaf --help` capture or hand-maintained).
- Man page: `docs/digaard.1` (installed via `justfile` + package rules if the tool is packaged).
- Update root `README.md` to list `digaard` alongside other workspace members.

---

## Risks & open questions

1. **DoQ ecosystem maturity** — `quinn` is stable, but the DoQ RFC (9250) is recent and interop-testing against real resolvers (AdGuard, Cloudflare) will be needed. Risk of transport-layer surprises. Mitigation: keep `--tls-insecure` and `--hex` early for debugging.
2. **DNSSEC validation surface** — building a correct validator is non-trivial (NSEC3 iteration bounds, algorithm rollover, negative caching). Scope for M6 is validation of the queried name only, not building a persistent validator. If this proves too large, split into M6a (records-only display) and M6b (validation).
3. **`bpaf` and `+shortcut` interplay** — `bpaf` doesn't natively grok `dig`-style `+foo` tokens. The pre-pass approach is simple but hides one token from `bpaf`'s help generation. Alternative: define each `+foo` as a hidden `bpaf` flag. To be decided in M7.
4. **Binary size** — DoQ pulls in `quinn` + `rustls` (already present) + `quinn-proto`. Even under a relaxed profile, the binary will be several MB. Acceptable for a dev tool, but worth measuring so users are not surprised.
5. **Feature-gating for slim builds** — while the plan is "relaxed", it's easy to add `default-features = ["doq", "color"]` and let advanced users compile without them. Not planned for M1-M7 but designed to accommodate later.
6. **Config-file precedence** — if the workspace grows more CLI tools with configs, consider a shared `dgaard-cli-config` helper. Deferred.

---

## Success criteria (v0.1.0)

- `digaard example.com` returns a correct `A` record via UDP against a public resolver.
- `digaard -s https://dns.quad9.net/dns-query -t MX example.com` returns MX records via DoH.
- `digaard -s quic://dns.adguard.com -t AAAA example.com` returns AAAA via DoQ.
- `cat domains.txt | digaard -f - -j 32 --stats --format json` fans out 1000 queries and prints one JSON object per line plus a summary block on stderr.
- `digaard -x 8.8.8.8` returns `dns.google.` as a PTR answer.
- `digaard --dnssec --validate cloudflare.com` prints `SECURE` and shows RRSIG/DS.
- All of the above with `--color auto` producing readable, non-garbled ANSI on a TTY and clean text when redirected.
- `cargo nextest run -p digaard` — green.
- `cargo clippy -p digaard -- -D warnings` — clean.

---

## Ideas

- MaxMindDB to put a flag or 2-3 char country
- time for the query
- whois info
