# Roadmap — Web UI

Web UI embedded in `dgaard-monitor`. Same feature set as the TUI — live feed, top talkers, timelines, analytics, integrations — served as a single-page app from an embedded axum server running as an opt-in background thread.

**Stack:** Rust + axum · rust-embed for static assets · Alpine.js (embedded) · Chart.js (embedded) · Shared `AppState` from the main pipeline · SQLite for persistence.

## Module tree

```
dgaard-monitor/
├── assets/                   # Embedded at compile time via rust-embed
│   ├── index.html
│   ├── alpine.min.js
│   ├── chart.min.js
│   └── style.css
└── src/
    └── web/
        ├── mod.rs            # Thread spawn, axum router wiring, graceful shutdown
        ├── state.rs          # WebState: rolling query log, per-client counters, WS broadcast
        └── routes/
            ├── mod.rs
            ├── health.rs     # GET /api/v1/health
            ├── stats.rs      # GET /api/v1/stats
            ├── lists.rs      # GET /api/v1/lists
            ├── queries.rs    # GET /api/v1/queries
            ├── talkers.rs    # GET /api/v1/talkers
            ├── timelines.rs  # GET /api/v1/timelines
            └── ws.rs         # GET /ws  (WebSocket upgrade)
```

---

## Phase 1: Integration Scaffolding ✅

_Focus: Wire the web server into dgaard-monitor as an opt-in background thread._

- **Config**: Add `WebConfig` struct to `config.rs` — `listen` (default `127.0.0.1`), `port` (default `8083`), `token`, `history_size` (default `1000`). Add `[web]` section to `dgaard-monitor.example.toml`.
- **Cargo dependencies**: Add `axum`, `rust-embed`, `tokio-tungstenite` to `Cargo.toml`.
- **WebState**: `WebState` behind `Arc` — rolling query log (`VecDeque` capped at `history_size`), per-client counters (`DashMap<IpAddr, ClientStats>`), `tokio::sync::broadcast` sender for live WebSocket push. Shares `Arc<AppState>` (domain map, stats) from the main pipeline.
- **Ingestor task**: Subscribe to `AppState::subscribe()`. On each `StatEvent`: enrich domain hash → name via `domain_map`, push to the WebSocket broadcast channel, append to the rolling query log.
- **Thread spawn**: In `main.rs`, if `config.web.enabled`, spawn `web::start(Arc<AppState>, Arc<WebState>, WebConfig)` as a `tokio::task`. Log the listen address on startup.
- **Graceful shutdown**: Wire `SIGTERM` / `SIGINT` to `axum::serve(...).with_graceful_shutdown(...)`. Web thread failure is logged but does not crash the TUI process.

## Phase 2: Web Server ✅

_Focus: Serving the single-page app shell and wiring up axum._

- **Axum setup**: Build the router with shared `Arc<WebState>`, bind to `listen:port`, start with `axum::serve`.
- **Static asset embedding**: Integrate `rust-embed` to embed the `assets/` directory at compile time. Serve `GET /` → `index.html` and each asset at its filename path.
- **HTML shell**: Minimal `index.html` — viewport meta, load Alpine.js and Chart.js from embedded paths (`/alpine.min.js`, `/chart.min.js`), tab navigation skeleton, metric header placeholders.
- **Bearer auth middleware**: axum middleware that checks `Authorization: Bearer <token>` on all `/api/v1/*` and `/ws` routes. Returns HTTP 401 on mismatch.

## Phase 3: Live Event Pipeline ✅

_Focus: Bridging the main event stream to connected browsers via WebSocket._

- **Broadcast channel**: `tokio::sync::broadcast::channel` with a bounded capacity inside `WebState`. The ingestor task (1.4) is the sole sender; each WebSocket connection holds a receiver.
- **WebSocket endpoint** (`GET /ws`): Upgrade with `axum::extract::ws::WebSocket`. Subscribe to the broadcast channel; forward each `WebEvent` serialized as JSON. Drop lagging clients (lag > capacity) without crashing the server.
- **Alpine.js live feed**: `x-data` component that opens a `WebSocket` on mount, appends incoming events to a capped reactive array, renders the last 50 rows as a table with action colouring (green = allowed, red = blocked).

## Phase 4: Dashboard UI ✅

_Focus: Replicating the dgaard-monitor dashboard layout in HTML/Alpine.js._

- **Metric header**: Four stat cards polled every second via `fetch('/api/v1/stats')` — Total Queries, Blocked %, Active Clients, QPS. Implemented with Alpine.js `x-init` + `setInterval`.
- **Flag distribution panel**: Horizontal bar chart (CSS) or small Chart.js bar chart showing the top block reasons, updated on each `/api/v1/stats` poll.
- **Tab navigation**: Alpine.js `x-show` tabs — Dashboard, Queries, Talkers, Timelines, About. Active tab state stored in the URL hash for bookmarkability.
- **Dashboard tab**: Combines metric header (4.1), live feed (3.3), flag distribution (4.2), and a top-domains table.
- **About tab**: Project name, version injected at build time via `env!("CARGO_PKG_VERSION")`, repo URL, license Apache 2, key WebSocket and API endpoint reference.

## Phase 5: REST API ✅

_Focus: Backend endpoints that power the UI and allow external integration._

- **`GET /api/v1/health`**: Return HTTP 204 No Content.
- **`GET /api/v1/stats`**: Return JSON — `{ total, blocked, allowed, suspicious, qps, active_clients, top_domains: [...], top_reasons: [...] }`. Computed from `AppState`.
- **`GET /api/v1/queries`**: Return the rolling query log as a JSON array. Optional query params: `?limit=N&offset=M&client=<IP>&action=<blocked|allowed|suspicious>`.
- **`GET /api/v1/talkers`**: Return per-client stats — `[{ client, hostname, count, blocked, first_seen, last_seen }]`.
- **Input validation**: Reject invalid query params with HTTP 400. All errors return `{ "error": "..." }` JSON body.

## Phase 6: Queries & Talkers Tabs

_Focus: Interactive tables with filter, sort, and freeze, mirroring the TUI tabs._

- [ ] 6.1. **Queries tab**: Table fetched from `GET /api/v1/queries`. Columns: datetime, domain, client IP, action, flags. Alpine.js reactive filter by client IP or domain keyword. Full row highlight by action.
- [ ] 6.2. **Freeze toggle**: Button to pause live WebSocket updates for the Queries tab (equivalent to `space` in the TUI). Banner shown while frozen. Click again to resume.
- [ ] 6.3. **Talkers tab**: Table from `GET /api/v1/talkers`. Columns: client / hostname, total requests, blocked count, first seen, last seen. Client-side column sort.
- [ ] 6.4. **Reverse DNS**: Backend performs a reverse DNS lookup for local IPs via `hickory-resolver` and caches results in `WebState`. Surfaced in the `/api/v1/talkers` `hostname` field and the Queries tab.

## Phase 7: Timelines Tab

_Focus: 24-hour trend visualization with Chart.js._

- [ ] 7.1. **Bucketed aggregation**: In `WebState`, maintain 288 five-minute buckets (24 h × 12). Each ingestor event increments the current bucket's counters (total, blocked, suspicious).
- [ ] 7.2. **`GET /api/v1/timelines`**: Return the last N buckets as `[{ ts, total, blocked, suspicious }]`.
- [ ] 7.3. **Timelines tab UI**: Chart.js line chart with three series (total / blocked / suspicious). Auto-refreshes every 60 seconds.

## Phase 8: Data & Persistence

_Focus: Surviving restarts and enabling longer-term analytics._

- [ ] 8.1. **SQLite integration**: Open a WAL-mode SQLite database (`rusqlite`). Two tables: `dns_events` (72 h rolling log) and `dns_stats_hourly` (30-day aggregates). Reuses the `[persistence]` config already present in `dgaard-monitor.toml`.
- [ ] 8.2. **Persistence writer**: A background task that drains a secondary channel and writes events to `dns_events`, updating `dns_stats_hourly` each hour.
- [ ] 8.3. **DB-backed query history**: When `GET /api/v1/queries` receives `?from=<ts>&to=<ts>` params, query SQLite instead of the in-memory log.

## Phase 9: Integrations

_Focus: Outbound notifications mirrored from the TUI._

- [ ] 9.1. **Action hooks**: Configuration to define `on_block` triggers (same format as the existing forwarding hooks).
- [ ] 9.2. **Generic webhooks**: POST JSON payloads to external URLs (SOAR, Slack, etc.) on configured events.

## Phase 10: Misc

- [ ] 10.1. **List tab**: Browse blocked domains, TLDs, wildcards, and whitelist entries from the host index. Search input, filter by list type (whitelist / blacklist), sort.
- [ ] 10.2. **Country flags**: Resolve hosted domain IPs to country codes and display flags in the Queries tab.
- [ ] 10.3. **Beaconing detection**: Highlight client/domain pairs that repeat at suspiciously regular intervals.
