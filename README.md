# Dgaard

A suite of Rust tools for high-performance, privacy-first DNS filtering and network security. Designed for resource-constrained environments (OpenWrt, embedded routers) and SME networks alike.

---

## Packages

### [dgaard](./dgaard) — DNS Security Proxy *(main project)*

[![Crates.io](https://img.shields.io/crates/v/dgaard)](https://crates.io/crates/dgaard)

A heuristic DNS filtering proxy that goes beyond static blocklists. Instead of waiting for a threat to appear on a list, Dgaard analyses the mathematical and lexical structure of every domain in real time to detect and block malicious traffic proactively.

**Key capabilities:**

- **DGA detection** — Shannon Entropy and N-Gram models identify algorithmically generated domains (malware C2) before they appear on any blocklist.
- **Stratified filtering pipeline** — queries flow through a short-circuit funnel: whitelist → hot LRU cache → Bloom filter + rkyv zero-copy blocklists → heuristic engine. Each stage is orders of magnitude cheaper than the next.
- **Smart-IDN / Homograph protection** — decodes Punycode and blocks look-alike phishing domains.
- **DNS exfiltration & rebinding protection** — monitors TXT record entropy, CNAME chains, and subdomain volume; drops public queries that resolve to private IPs.
- **Behavioral analytics** — detects NXDOMAIN-hunting clients (botnet indicators) and DNS tunneling patterns.
- **Live telemetry** — streams length-prefixed binary events over a Unix Domain Socket for real-time dashboards.
- **OpenWrt-optimised** — binary under 5 MB, `SO_REUSEPORT` multi-threading, async Tokio runtime, zero-copy parsing with `rkyv`.

```bash
cargo install dgaard
dgaard --config /etc/dgaard/dgaard.toml
```

See the [dgaard README](./dgaard/README.md) and [example configuration](./dgaard/config.example.toml) for the full setup guide.

---

### [dgaard-monitor](./dgaard-monitor) — Real-Time TUI Dashboard

[![Crates.io](https://img.shields.io/crates/v/dgaard-monitor)](https://crates.io/crates/dgaard-monitor)

A terminal UI that connects to `dgaard`'s Unix Domain Socket and visualises DNS activity without adding any overhead to the proxy process. It resolves domain hashes back to human-readable names via a static mapping file, then renders live feeds, per-client traffic (Talkers), timeline charts, and top-N block statistics.

**Key capabilities:**

- Parses the length-prefixed binary protocol emitted by `dgaard` (`[u16: length][u8: type][payload]`).
- Watches the host-index file with `inotify` and hot-reloads domain mappings without restarting.
- Aggregates events into bucketed timelines with zoom cycling and gap-filling.
- Resolves client IPs to hostnames via reverse-DNS (PTR lookups) in the background.
- Linux only (relies on `inotify`).

```bash
cargo install dgaard-monitor

# attach to a running dgaard instance
dgaard-monitor --socket /tmp/dgaard_stats.sock --index /var/lib/dgaard/hosts.bin
```

See the [dgaard-monitor README](./dgaard-monitor/README.md) for the full protocol and configuration reference.

---

### [adblockptimize](./adblockptimize) — Adblock List Optimizer

[![Crates.io](https://img.shields.io/crates/v/adblockptimize)](https://crates.io/crates/adblockptimize)

A CLI tool that ingests standard adblock lists (files or URLs) and splits them into two deduplicated, sorted outputs: one for **network-level** blocking (DNS, dnsmasq, Unbound, Pi-hole, AdGuard Home) and one for **browser-level** blocking (CSS/JS/HTML cosmetic rules). Feeding the network output directly into `dgaard` gives you cleaner, smaller blocklists with no browser-specific noise.

```bash
cargo install adblockptimize

# split a list into network and browser files
adblockptimize https://example.com/list.txt local-list.txt

# dnsmasq format, network rules only
adblockptimize --no-browser --format=dnsmasq https://example.com/list.txt

# custom output file names
adblockptimize --network-file=dns.txt --browser-file=ublock.txt https://example.com/list.txt
```

See the [adblockptimize README](./adblockptimize/README.md) for the full format and target compatibility table.

---

## Architecture

```
adblockptimize          dgaard-monitor
      |                       |
      | (optimised lists)     | (Unix socket telemetry)
      v                       |
   dgaard  <-----------------/
(DNS proxy, port 5353)
      |
   dnsmasq / router DNS
      |
   LAN clients
```

`adblockptimize` pre-processes upstream adblock lists into compact, DNS-ready formats that `dgaard` can ingest. `dgaard-monitor` connects to `dgaard`'s telemetry socket and provides a live view of what is happening on the network — all three tools are designed to work together but can be used independently.

---

## Installation

All packages are published to [crates.io](https://crates.io) and can be installed with Cargo:

```bash
cargo install dgaard
cargo install dgaard-monitor   # Linux only
cargo install adblockptimize
```

Pre-built binaries for Linux (musl), macOS, and Windows are available on the [Releases](../../releases) page. Each package is released independently and tagged `<package>-v<version>`.

---

## Building from source

```bash
git clone https://codeberg.org/slundi/dgaard
cd dgaard

# build all packages
cargo build --release

# build a specific package
cargo build --release -p dgaard
cargo build --release -p dgaard-monitor
cargo build --release -p adblockptimize
```

Cross-compilation via [`cross`](https://github.com/cross-rs/cross):

```bash
cargo install cross --git https://github.com/cross-rs/cross

cross build --release --target aarch64-unknown-linux-musl -p dgaard
cross build --release --target armv7-unknown-linux-musleabihf -p dgaard
```

---

## License

Apache-2.0 — see each package's `Cargo.toml` for details.

Repository: <https://codeberg.org/slundi/dgaard>
