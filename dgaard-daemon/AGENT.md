# Agent Instructions: dgaard-daemon

You are working on **dgaard-daemon**, a Unix socket sidecar that fronts `dgaard-engine`.

## Architectural Constraints

- **One connection, one domain, one response.** The protocol is stateless. Do not add session state, multiplexing, or pipelining.
- **Never crash on bad input.** Malformed domains, oversized inputs, and IO errors must produce a `{"error":"..."}` JSON line, not a panic. Use `log::warn!` for recoverable errors.
- **No DNS resolution.** Call `dgaard_engine::resolve_with_score` with the raw trimmed domain string — no UDP sockets, no upstream queries.
- **`Arc<ArcSwap<T>>` for reload.** `FilterEngine` and `Config` are wrapped in `Arc<ArcSwap<T>>`. SIGHUP replaces the inner `Arc` atomically. Never swap to a broken state — keep the current engine and log a warning if reload fails.

## Rules

- Max domain length is 253 bytes (RFC 1035). Reject longer input before calling the engine.
- Socket permissions must be `0o600` — set after `bind`, not before.
- Remove stale socket file before binding.
- Drain all in-flight tasks before the process exits.

## Testing

- Unit tests in `src/handler.rs` — cover every `Action` and `BlockReason` variant.
- Integration tests in `tests/socket.rs` — use real `UnixListener`/`UnixStream` pairs, no mocking.
- Run with `cargo nextest run -p dgaard-daemon`.
