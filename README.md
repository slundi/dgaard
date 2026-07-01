# Dgaard

A suite of Rust tools for high-performance, privacy-first DNS filtering and network security. Designed for resource-constrained environments (OpenWrt, embedded routers) and SME networks alike.

---

## Packages

### [dgaard](./dgaard) — DNS Security Proxy _(main project)_

[![Crates.io](https://img.shields.io/crates/v/dgaard)](https://crates.io/crates/dgaard)

A heuristic DNS filtering proxy and server (with recursive resolver) that goes beyond static blocklists. Instead of waiting for a threat to appear on a list, Dgaard analyses the mathematical and lexical structure of every domain in real time to detect and block malicious traffic proactively.

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

### [dgaard-daemon](./dgaard-daemon) — Unix-Socket Engine Sidecar _(binary)_

A ready-made daemon that wraps `dgaard-engine` behind a Unix Domain Socket. Each connection sends one newline-terminated domain and receives a newline-terminated JSON verdict (`score`, `blocked`, `action`, `reasons`). No DNS resolution is performed — the daemon only scores domain strings against the engine's static filters and heuristics.

**Designed as a sidecar for:**

- **MTAs and spam filters** — Postfix policy daemons, Rspamd modules, or any local process that can write to a Unix socket.
- **Language interop** — Python, Go, shell (`socat`) can call the engine without linking Rust.

**Key properties:**

- Stateless wire protocol — one domain per connection, reconnect for each query.
- `SIGHUP` atomically reloads `dgaard-engine` config and rebuilds the `FilterEngine` via `arc-swap`.
- Socket created with `0o600` permissions; config discovery via `--config`, `/etc/dgaard-daemon/dgaard-daemon.toml`, or `./dgaard-daemon.toml`.

See the [dgaard-daemon README](./dgaard-daemon/README.md) for the wire protocol and signal reference.

---

### [dgaard-rest](./dgaard-rest) — HTTP REST API for the Engine _(binary)_

A standalone HTTP server that exposes `dgaard-engine` scoring over JSON. Aimed at dashboards, web services, and any tool that speaks HTTP but cannot embed the Rust library directly. Does **not** perform DNS resolution.

**Endpoints:**

- `POST /api/v1/check` — score a domain, returns `score`, `blocked`, `action`, `reasons`.
- `GET  /api/v1/blocklists` — metadata (mtime, entry count) for every configured blocklist and whitelist.
- `POST /api/v1/blocklists/update` — async reload from disk; engine swap is atomic via `arc-swap`.
- `GET  /api/v1/health` — `204 No Content` liveness probe.

**Key properties:**

- `axum` on top of `dgaard-engine`; `SIGHUP` atomically reloads config.
- Configurable status code for blocked domains (`200` or `403`), 253-byte domain length cap enforced with `422`.
- Config discovery via `--config`, `/etc/dgaard-rest/dgaard-rest.toml`, or `./dgaard-rest.toml`.

See the [dgaard-rest README](./dgaard-rest/README.md) for the endpoint reference.

---

### [dgaard-monitor](./dgaard-monitor) — Telemetry Monitor _(binary)_

[![Crates.io](https://img.shields.io/crates/v/dgaard-monitor)](https://crates.io/crates/dgaard-monitor)

The umbrella binary that connects to `dgaard`'s Unix Domain Socket, resolves domain hashes via the static mapping file, and fans events out to one or more frontends. Frontends are cargo features so binaries only ship what they use.

**Feature flags:**

- `tui` _(default)_ — real-time Ratatui dashboard, provided by [`dgaard-monitor-tui`](#dgaard-monitor-tui--tui-frontend-library).
- `rest` _(default)_ — HTTP API, WebSocket stream, embedded web UI, and MCP server, provided by [`dgaard-monitor-rest`](#dgaard-monitor-rest--restwebsocketmcp-frontend-library).
- `nats` — publishes events to a NATS subject, provided by [`dgaard-monitor-nats`](#dgaard-monitor-nats--nats-publisher-library).

All frontends share the protocol, state store, storage, and IO layer from [`dgaard-monitor-core`](#dgaard-monitor-core--shared-monitor-library). Linux only (relies on `inotify` for hot-reloading the host-index).

See the [dgaard-monitor README](./dgaard-monitor/README.md) for the full protocol and configuration reference.

---

### [dgaard-monitor-core](./dgaard-monitor-core) — Shared Monitor Library

The core primitives every monitor frontend depends on, with **zero HTTP, UI, or sink concerns of its own**. Split out of `dgaard-monitor` so the TUI, REST/WS/MCP, and NATS frontends can be composed independently or embedded elsewhere.

**Provides:**

- **Protocol** — parser for `dgaard`'s length-prefixed binary stream (`[u16 length][u8 type][payload]`).
- **State** — in-memory aggregation of live feeds, per-client Talkers, bucketed timelines.
- **Storage** — `rusqlite` (bundled) persistence layer.
- **IO / forwarding** — Unix-socket client, `inotify`-based host-index hot-reload, event fan-out.

---

### [dgaard-monitor-tui](./dgaard-monitor-tui) — TUI Frontend Library

Ratatui + Crossterm dashboard on top of `dgaard-monitor-core`. Renders live feeds, per-client Talkers, timeline charts with zoom/gap-filling, and top-N block statistics; runs background PTR lookups for client hostnames via `hickory-resolver`. Consumed by `dgaard-monitor` when the `tui` feature is enabled.

---

### [dgaard-monitor-rest](./dgaard-monitor-rest) — REST/WebSocket/MCP Frontend Library

`axum`-based HTTP frontend on top of `dgaard-monitor-core`. Exposes:

- A **REST API** for querying live state and history.
- A **WebSocket** stream that mirrors the binary telemetry feed to browsers.
- An embedded **web UI** (via `rust-embed`) so a single binary self-serves the dashboard.
- An **MCP server** (`rust-mcp-sdk`) that makes the same state queryable by LLM tooling.

Consumed by `dgaard-monitor` when the `rest` feature is enabled.

---

### [dgaard-monitor-nats](./dgaard-monitor-nats) — NATS Publisher Library

Bridges the monitor's event stream to a [NATS](https://nats.io) server via `async-nats`. Each parsed event is serialised as JSON and published to a configurable subject so external services can subscribe without holding a Unix socket. Consumed by `dgaard-monitor` when the `nats` feature is enabled.

---

### [adblockptimize](./adblockptimize) — Adblock List Optimizer

[![Crates.io](https://img.shields.io/crates/v/adblockptimize)](https://crates.io/crates/adblockptimize)

A CLI tool that ingests standard adblock lists (files or URLs) and splits them into two deduplicated, sorted outputs: one for **network-level** blocking (DNS, dnsmasq, Unbound, Pi-hole, AdGuard Home) and one for **browser-level** blocking (CSS/JS/HTML cosmetic rules). Feeding the network output directly into `dgaard` (or other network ad blocker) gives you cleaner, smaller blocklists with no browser-specific noise.

See the [adblockptimize README](./adblockptimize/README.md) for the full format and target compatibility table.

---

### [list-stats](./list-stats) — Blocklist Statistics & Overlap Analyzer

A standalone binary that ingests DNS blocklists (built-in sources or user-supplied files/URLs) and produces per-list, per-category, and global statistics as **JSON + CSV**, plus a static **ECharts** HTML dashboard that reads the JSON.

**Computes:**

- Entry counts split by type (plain / wildcard / regex).
- Top TLDs and tokenised word frequencies per list, per category, and globally.
- **Overlap matrix** between every pair of lists (shared entries + percentage) — useful for picking a minimal non-redundant blocklist set.

Built-in sources cover uBlockOrigin, StevenBlack, and oisd, categorised as ads / privacy / malware / annoyances / fake-news / gambling / porn.

See the [list-stats README](./list-stats/README.md) for the output schema and CLI options.

---

## Architecture

See [docs/Architecture.md](docs/Architecture.md).

---

## History & motivations

How Dgaard grew from a single DNS proxy into this multi-crate workspace, and why the pieces are shaped the way they are: see [docs/History.md](docs/History.md).

---

## Installation

See [available methods](docs/Install.md).
