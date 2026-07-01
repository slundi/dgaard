# Dgaard

A suite of Rust tools for high-performance, privacy-first DNS filtering and network security. Designed for resource-constrained environments (OpenWrt, embedded routers) and SME networks alike.

---

## Packages

### [dgaard](./dgaard) — DNS Security Proxy _(main project)_

[![Crates.io](https://img.shields.io/crates/v/dgaard)](https://crates.io/crates/dgaard)

A heuristic DNS filtering proxy that goes beyond static blocklists. Instead of waiting for a threat to appear on a list, Dgaard analyses the mathematical and lexical structure of every domain in real time to detect and block malicious traffic proactively.

**Key capabilities:**

- **DGA detection** — Shannon Entropy and N-Gram models identify algorithmically generated domains (malware C2) before they appear on any blocklist.
- **Stratified filtering pipeline** — queries flow through a short-circuit funnel: whitelist → hot LRU cache → Bloom filter + rkyv zero-copy blocklists → heuristic engine. Each stage is orders of magnitude cheaper than the next.
- **Smart-IDN / Homograph protection** — decodes Punycode and blocks look-alike phishing domains.
- **DNS exfiltration & rebinding protection** — monitors TXT record entropy, CNAME chains, and subdomain volume; drops public queries that resolve to private IPs.
- **Behavioral analytics** — detects NXDOMAIN-hunting clients (botnet indicators) and DNS tunneling patterns.
- **GeoIP suspicion scoring** — checks each resolved IP against a local MaxMind-format MMDB database; responses from high-risk jurisdictions add weighted points to the domain's cumulative threat score, catching new malware infrastructure regardless of whether it has appeared on any blocklist.
- **Custom threat-intelligence flags** _(requires `custom_flags` feature)_ — map up to 16 organisation-specific domain lists (AI-generated feeds, sector threat intel, proprietary sources) to named bitflags, each with its own suspicion weight; flags propagate through the telemetry stream for dashboard and SIEM correlation.
- **Live telemetry** — streams length-prefixed binary events over a Unix Domain Socket for real-time dashboards.
- **OpenWrt-optimised** — binary under 5 MB, `SO_REUSEPORT` multi-threading, async Tokio runtime, zero-copy parsing with `rkyv`.

See the [dgaard README](./dgaard/README.md) and [example configuration](./dgaard/config.example.toml) for the full setup guide.

---

### [dgaard-engine](./dgaard-engine) — Embeddable Filtering Engine _(library)_

The pure-Rust filtering engine extracted from `dgaard` as a standalone `[lib]` crate. It contains the complete analysis and decision pipeline — blocklists, DGA detection, entropy/N-Gram scoring, lexical heuristics, and policy checks — with **no async runtime and no networking dependencies**. Any Rust application can embed it directly.

**Designed for:**

- **MTA spam filtering** — call `resolve_with_score` from your mail pipeline to score domains in envelope/header/body.
- **HTTP proxy / web service** — expose the engine as a REST endpoint without pulling in Tokio or Hyper.
- **Custom tooling** — integrate DNS-level threat intelligence into any Rust binary.

**Key properties:**

- No `tokio`, `hyper`, or `rustls` — sync-friendly, zero async overhead.
- All state is explicit: `FilterEngine` and `Config` are plain structs passed by reference; no global statics.
- `FilterEngine` carries its own `seed: u64` so multiple independent instances can coexist safely.

See the [dgaard-engine README](./dgaard-engine/README.md) for the full API reference.

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

See the [dgaard-monitor README](./dgaard-monitor/README.md) for the full protocol and configuration reference.

---

### [adblockptimize](./adblockptimize) — Adblock List Optimizer

[![Crates.io](https://img.shields.io/crates/v/adblockptimize)](https://crates.io/crates/adblockptimize)

A CLI tool that ingests standard adblock lists (files or URLs) and splits them into two deduplicated, sorted outputs: one for **network-level** blocking (DNS, dnsmasq, Unbound, Pi-hole, AdGuard Home) and one for **browser-level** blocking (CSS/JS/HTML cosmetic rules). Feeding the network output directly into `dgaard` (or other network ad blocker) gives you cleaner, smaller blocklists with no browser-specific noise.

See the [adblockptimize README](./adblockptimize/README.md) for the full format and target compatibility table.

---

## Architecture

See [docs/Architecture.md](docs/Architecture.md).

---

## Installation

See [available methods](docs/Install.md).
