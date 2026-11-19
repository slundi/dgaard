# dgaard-monitor — notes for agents

`dgaard-monitor` reads the binary telemetry stream of the dgaard DNS proxy
from a Unix socket, resolves domain hashes to names, and fans each event out
to sinks: TUI or headless JSON, SQLite, forwarding (file/HTTP), REST/WebSocket/
MCP/web UI, and NATS federation. Everything below is checked against the code;
when in doubt, the code wins — fix this file in the same change.

## Crates

| Crate                 | Role                                                                                                                                                         |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `dgaard-monitor`      | The binary: `cli.rs` (bpaf), `config.rs` (TOML via `toml-span`), `main.rs` (wiring), `lifecycle.rs` (stop + shutdown), `headless.rs`, `custom_flags.rs`.     |
| `dgaard-monitor-core` | Shared logic: `protocol.rs` (wire frames), `io/` (socket reader, host index, inotify watcher), `state.rs` (`AppState`), `db.rs`, `forwarding.rs`, `util.rs`. |
| `dgaard-monitor-tui`  | ratatui TUI (feature `tui`).                                                                                                                                 |
| `dgaard-monitor-rest` | REST API, WebSocket, MCP and embedded web UI (feature `rest`).                                                                                               |
| `dgaard-monitor-nats` | NATS publisher/subscriber (feature `nats`).                                                                                                                  |

Default features: `tui`, `rest`. The monitor does not depend on `dgaard-engine`
(only as a dev-dependency, to test that default paths match dgaard's).

## Data flow

1. **Host index** (`io/index.rs`): `DGHI` v1 file written by dgaard
   (`sources.host_index_path`, default `/var/dgaard/host_mapping.bin`), loaded at
   startup and reloaded by `io/watcher.rs`, which watches the **parent
   directory** (dgaard replaces the file with `rename(2)`).
2. **Socket** (`io/socket.rs::run_reader`): frames are
   `[len: u16 LE][type: u8][payload]`, `len` ≤ `MAX_FRAME_PAYLOAD` (4096).
   Type `0x00` = `DomainMapping { hash: u64, domain }`, `0x01` = `Event`; an
   event may end with a 2-byte ASCII country (GeoIP of the answer, sent when
   dgaard's `[security.geo_ip]` is on). Readers ignore trailing bytes they do
   not know, so new fields go at the end. A complete frame the monitor does
   not understand is skipped, never a reason to reconnect. Reconnects use
   `Backoff` (100 ms → 30 s, jitter). The peer's UID is checked before
   reading (`PeerPolicy`, `[input] peer_uid`).
3. **State** (`state.rs::AppState`): `domain_map` merges three sources with
   this precedence: socket mappings > host index > NATS peers (capped,
   never rename a known hash). Two broadcast buses: `subscribe()` (every
   event) and `subscribe_local()` (only the local daemon's — the NATS
   publisher reads this one so remote events are never re-published).
4. **Sinks** subscribe to the bus. Losses are counted per sink (`Sink`,
   `record_drop`) and shown in web `/stats` and at shutdown.

`StatBlockReason` is a `u32` bitmask: bits 0–15 are built in, 16–31 are
custom flags labelled from dgaard's `[[security.custom_flags]]`
(`input.engine_config_path`). Use `util::reason_labels`, `format_client_ip`
(IPv4 arrives as IPv4-mapped IPv6) and `action_name` everywhere instead of
local copies.

## Invariants (each one was a bug)

- **stdout belongs to the TUI or to the headless JSON stream** — one JSON
  object per line, nothing else. Diagnostics go to stderr. Forwarding never
  writes to stdout. Without a terminal on stdout the monitor runs headless.
- **Never hold a lock across I/O** (e.g. the `domain_map` guard while
  writing to stdout).
- **Sinks must listen before events flow**: `main` starts the socket reader
  last and waits for `bus_sinks` subscribers. Add a new bus sink to that
  count. In tests, use `AppState::wait_for_subscribers`, not `sleep`.
- **Every way out runs `lifecycle::shutdown`** (SQLite flush, WAL
  checkpoint) within one deadline; never call `process::exit` from a task.
- **NATS input is untrusted**: validate the whole event before touching
  state (`validate_inbound`); peers never overwrite mappings.
- **The NATS wire format is versioned** (`v`, absent = 1): additive changes
  keep `v`; unknown actions and versions are skipped and counted.

## Configuration

Parsing is strict (`config.rs`): unknown sections/keys and out-of-range
values are errors with line and column; sections of features not compiled in
only warn. Adding or changing a key means updating, in the same change:

1. `dgaard-monitor/src/config.rs` (parser + tests),
2. `dgaard-monitor/dgaard-monitor.example.toml`,
3. `nix/modules/dgaard-monitor.nix` and `nix/tests/dgaard-monitor.nix`,
4. `dgaard-web-configurator/js/schema/monitor.js`, then `just configurator-golden`
   (`schema-coverage.test.js` fails otherwise).

CLI: `-c/--config`, `-s/--socket`, `-i/--index`, `-d/--db`, `-H/--headless`;
path flags override the config (`Opts::apply_overrides`).

## Checks

```bash
cargo nextest run -p dgaard-monitor-core -p dgaard-monitor-nats -p dgaard-monitor \
  -p dgaard-monitor-rest -p dgaard-monitor-tui --features dgaard-monitor/nats
cargo nextest run -p dgaard-monitor --no-default-features   # feature-gated code
cargo clippy --all-targets --all-features -- -D warnings      # just lint
just configurator-test                                        # schema/golden files
nix build .#checks.x86_64-linux.dgaard-monitor-module         # NixOS module
```

Binary-level tests live in `dgaard-monitor/tests/` (they spawn the real
binary against a fake dgaard socket); NATS federation tests use the mock
broker in `dgaard-monitor-nats/tests/mock_nats/`.
