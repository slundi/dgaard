# Roadmap — dgaard-monitor refactor (workspace split)

## Motivation

`dgaard-monitor` currently bundles four sub-systems with very different
lifetimes into a single crate (~12k LoC of Rust):

| Sub-system     | LoC   | Concern                                      |
|----------------|-------|----------------------------------------------|
| ingest+storage | ~1.0k | daemon work — UDS socket, host index, SQLite |
| TUI            | ~3.6k | ratatui terminal UI                          |
| web (axum)     | ~2.4k | REST + WebSocket + embedded SPA              |
| connectivity   | ~2.3k | MCP server, NATS sink, WS, API helpers       |

The crate isn't huge, but it conflates daemon responsibilities with three
independent frontends. We want to be able to **enable or disable each
frontend** (TUI, REST/WS/MCP umbrella, NATS) without paying its compile-time
or binary-size cost — and to keep the daemon's core surface clean.

## Decisions (locked in)

1. **Workspace split, not a binary split.** Frontends still run in-process
   and share `Arc<AppState>` directly. No IPC protocol invented for this
   refactor.
2. **No rewrite.** Modules move as-is; imports and Cargo manifests change.
3. **`dgaard-monitor-nats` is its own crate**, not a feature inside core.
   Keeps the NATS dep off non-NATS builds.
4. **REST + WebSocket + MCP share a single axum `Router`** on one listener.
   Today MCP runs on its own hyper server; that becomes a bridge onto axum.
5. **Naming.** The new HTTP umbrella crate is `dgaard-monitor-rest`.
   The existing top-level `dgaard-rest` (which fronts `dgaard-engine`) is
   unrelated and stays put.

## Target workspace layout

```
dgaard-monitor/                  binary — arg parsing, config load, wire-up
  src/{main,cli,headless,config}.rs

dgaard-monitor-core/             daemon core, no HTTP / UI / MCP
  src/protocol.rs                StatEvent / StatAction / StatBlockReason
  src/state.rs                   AppState (shared via Arc)
  src/db.rs                      SQLite + WAL + retention
  src/forwarding.rs              webhook sink (daemon-side dispatcher)
  src/io/{mod,socket,watcher,index}.rs
  src/{util,error}.rs
  src/config.rs                  CoreConfig only

dgaard-monitor-rest/             REST + WS + MCP, shared axum Router
  src/lib.rs                     pub fn serve(cfg, state, shutdown)
  src/router.rs                  build_router(state) -> axum::Router
  src/state.rs                   WebState wrapping Arc<AppState>
  src/routes/*.rs                about/beaconing/health/lists/queries/
                                 stats/talkers/timeline
  src/ws.rs                      WebSocket upgrade + ticket auth
  src/mcp/{server,auth}.rs       rust-mcp-sdk handler bridged onto axum
  src/rdns.rs                    PTR resolver for Talkers tab
  src/config.rs                  RestConfig
  assets/                        embedded SPA (rust-embed)

dgaard-monitor-nats/             NATS publisher sink
  src/lib.rs                     pub async fn run(cfg, state, shutdown)
  src/config.rs                  NatsConfig

dgaard-monitor-tui/              ratatui frontend
  src/lib.rs                     pub async fn run(cfg, state, shutdown)
  src/{app,keys,layout,util}.rs
  src/tabs/*.rs
  src/widgets/*.rs
  src/config.rs                  TuiConfig
```

Each frontend crate:

- depends on `dgaard-monitor-core`
- owns its own `*Config` struct (no leakage of HTTP/UI/NATS concerns into core)
- exposes a single `async fn run(cfg, state: Arc<AppState>, shutdown: watch::Receiver<bool>)`
- is selectable via a Cargo feature on `dgaard-monitor` **and** a runtime
  `[section] enabled = true` toggle in the TOML config

## Cargo workspace edits

```toml
# Cargo.toml
[workspace]
members = [
  "adblockptimize",
  "dgaard",
  "dgaard-daemon",
  "dgaard-engine",
  "dgaard-monitor",
  "dgaard-monitor-core",   # NEW
  "dgaard-monitor-rest",   # NEW
  "dgaard-monitor-nats",   # NEW
  "dgaard-monitor-tui",    # NEW
  "dgaard-rest",
  "list-stats",
]
```

Move into `[workspace.dependencies]` (currently inlined in
`dgaard-monitor/Cargo.toml`): `rust-mcp-sdk`, `tokio-tungstenite`,
`rust-embed`, `constant_time_eq`, `rusqlite`.

Add path entries:

```toml
dgaard-monitor-core = { path = "dgaard-monitor-core" }
dgaard-monitor-rest = { path = "dgaard-monitor-rest" }
dgaard-monitor-nats = { path = "dgaard-monitor-nats" }
dgaard-monitor-tui  = { path = "dgaard-monitor-tui"  }
```

Feature gates in `dgaard-monitor/Cargo.toml`:

```toml
[features]
default = ["tui", "rest"]
tui  = ["dep:dgaard-monitor-tui"]
rest = ["dep:dgaard-monitor-rest"]
nats = ["dep:dgaard-monitor-nats"]
```

## File move map

| From `dgaard-monitor/src/…`                          | To                                                           |
|------------------------------------------------------|--------------------------------------------------------------|
| `protocol.rs`                                        | `dgaard-monitor-core/src/protocol.rs`                        |
| `state.rs`                                           | `dgaard-monitor-core/src/state.rs`                           |
| `db.rs`                                              | `dgaard-monitor-core/src/db.rs`                              |
| `forwarding.rs`                                      | `dgaard-monitor-core/src/forwarding.rs`                      |
| `error.rs`, `util.rs`                                | `dgaard-monitor-core/src/`                                   |
| `io/{mod,socket,watcher,index}.rs`                   | `dgaard-monitor-core/src/io/`                                |
| `config.rs` → `CoreConfig`                           | `dgaard-monitor-core/src/config.rs`                          |
| `config.rs` → `TuiConfig`                            | `dgaard-monitor-tui/src/config.rs`                           |
| `config.rs` → `WebConfig`+`ConnectivityConfig` merged → `RestConfig` | `dgaard-monitor-rest/src/config.rs`          |
| `config.rs` → `NatsConfig`                           | `dgaard-monitor-nats/src/config.rs`                          |
| `web/{mod,state,rdns}.rs`                            | `dgaard-monitor-rest/src/`                                   |
| `web/routes/*.rs`                                    | `dgaard-monitor-rest/src/routes/`                            |
| `web/routes/ws*.rs` + `connectivity/websocket.rs`    | `dgaard-monitor-rest/src/ws.rs` (collapse duplicates)        |
| `connectivity/api.rs`                                | `dgaard-monitor-rest/src/` (it's HTTP, not NATS)             |
| `connectivity/mcp.rs`                                | `dgaard-monitor-rest/src/mcp/server.rs`                      |
| `connectivity/mcp_token_auth_provider.rs`            | `dgaard-monitor-rest/src/mcp/auth.rs`                        |
| `connectivity/nats.rs`                               | `dgaard-monitor-nats/src/lib.rs`                             |
| `tui/**`                                             | `dgaard-monitor-tui/src/`                                    |
| `assets/`                                            | `dgaard-monitor-rest/assets/`                                |
| `cli.rs`, `main.rs`, `headless.rs`                   | stay in `dgaard-monitor/`                                    |

## Binary wire-up sketch

```rust
// dgaard-monitor/src/main.rs
let cfg = Config::load(&cli.config)?;
let (shutdown_tx, shutdown_rx) = watch::channel(false);

let state = Arc::new(AppState::new(&cfg.core)?);
spawn_ingest(state.clone(), &cfg.core, shutdown_rx.clone());

#[cfg(feature = "rest")]
if let Some(rest) = cfg.rest.as_ref().filter(|c| c.enabled) {
    tokio::spawn(dgaard_monitor_rest::run(
        rest.clone(), state.clone(), shutdown_rx.clone(),
    ));
}

#[cfg(feature = "nats")]
if let Some(nats) = cfg.nats.as_ref().filter(|c| c.enabled) {
    tokio::spawn(dgaard_monitor_nats::run(
        nats.clone(), state.clone(), shutdown_rx.clone(),
    ));
}

#[cfg(feature = "tui")]
if let Some(tui) = cfg.tui.as_ref().filter(|c| c.enabled) {
    dgaard_monitor_tui::run(tui.clone(), state.clone(), shutdown_rx).await?;
} else {
    headless::wait_for_signal(shutdown_tx).await;
}
```

## Shared axum Router (REST + WS + MCP)

`dgaard-monitor-rest` exposes:

```rust
pub fn build_router(state: Arc<AppState>) -> axum::Router {
    axum::Router::new()
        .nest("/api/v1", routes::api_router())   // existing REST endpoints
        .route("/api/v1/ws",        get(ws::upgrade))
        .route("/api/v1/ws/ticket", post(ws::issue_ticket))
        .nest("/mcp", mcp::router(state.clone()))
        .route("/healthz", get(routes::health::get))
        .with_state(WebState::new(state))
}

pub async fn run(cfg: RestConfig, state: Arc<AppState>, mut shutdown: watch::Receiver<bool>) {
    let app = build_router(state);
    axum::serve(TcpListener::bind(cfg.listen).await?, app)
        .with_graceful_shutdown(async move { shutdown.changed().await.ok(); })
        .await?;
}
```

The only non-trivial bit is bridging `rust-mcp-sdk` onto axum. Today
`connectivity/mcp.rs` calls `hyper_server::create_server(...)` which owns its
own listener. We need to instead obtain the SDK's tower `Service` (or wrap
its handler in an axum `any` route) and `.nest("/mcp", …)` it. The exact API
call depends on the pinned `rust-mcp-sdk` version — to be confirmed during
step 6.

## Execution order (lowest-risk path)

Each step compiles, tests, and ships green on its own. No big-bang.

1. **Skeleton:** create empty `dgaard-monitor-core` crate, move `protocol.rs`
   only, update imports across `dgaard-monitor`. Validates the workspace
   topology and `[workspace.dependencies]` plumbing.
2. **Daemon core:** move `state.rs`, `db.rs`, `util.rs`, `error.rs`,
   `io/{socket,watcher,index}.rs`, `forwarding.rs` into
   `dgaard-monitor-core`. After this step, `dgaard-monitor` still owns all
   frontends but imports core types from the new crate.
3. **Config split:** carve `TuiConfig` / `RestConfig` / `NatsConfig` out of
   `config.rs`. Keep `Config::load` (and the TOML parser) in the binary,
   importing sub-structs from each frontend crate. The fiddly step.
4. **Extract `dgaard-monitor-nats`** — smallest frontend, lowest blast
   radius. Verifies the `run(cfg, state, shutdown)` contract.
5. **Extract `dgaard-monitor-tui`** — bigger but self-contained, no HTTP
   surface to redesign.
6. **Extract `dgaard-monitor-rest`** — last because it's the largest, and
   includes the MCP-onto-axum bridge. Merges the two `WebSocket` paths
   (`connectivity/websocket.rs` vs `web/routes/ws*.rs`) into one.
7. **Feature flags + CI matrix:** wire `default = ["tui", "rest"]` and
   verify `cargo build -p dgaard-monitor --no-default-features` (headless,
   no frontends) and `--features nats` succeed. Add the matrix to CI.

## Open questions / things to nail down during work

- **MCP-on-axum API surface.** Pin the exact `rust-mcp-sdk` integration
  pattern (`tower::Service` adapter vs raw `axum::any` route). Investigate
  in step 6.
- **`assets/` ownership.** Today `rust-embed` embeds the SPA at compile time
  in `dgaard-monitor`. After the move, it lives in
  `dgaard-monitor-rest/assets/` and is embedded by that crate. Verify the
  embed path is relative to `CARGO_MANIFEST_DIR`.
- **Two WebSocket paths today** (`connectivity/websocket.rs` and
  `web/routes/ws*.rs`) — confirm which one is live and delete the dead one
  during step 6, don't carry both forward.
- **`headless.rs`** stays in the binary but currently imports from `web/`
  and `connectivity/`. Audit during step 6 — it may become a thin
  "no frontends enabled, just block on signal" helper.
- **Dockerfile.** Update the build stage to `cargo build -p dgaard-monitor`
  (path unchanged) and verify the `COPY --from=builder` step still finds
  the binary at the same path.

## Out of scope

- Splitting frontends into separate binaries (talking to the daemon over
  NATS or a Unix socket). Possible follow-up if we ever want to run the TUI
  on a different host than the daemon.
- Replacing SQLite, changing the wire protocol, or any feature work.
- Renaming the top-level `dgaard-rest` crate (it's unrelated, stays as-is).
