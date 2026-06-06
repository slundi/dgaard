# Agent Instructions: dgaard-rest

You are working on **dgaard-rest**, an HTTP REST server that fronts `dgaard-engine` using `axum`.

## Architectural Constraints

- **Axum shared state only.** All mutable state lives in `AppState` behind `Arc<ArcSwap<T>>`. Do not use global statics or thread-locals.
- **Never crash on bad input.** All validation errors return structured JSON `{"error":"..."}` via `ApiError`. Centralise new error variants there — do not return raw strings or plain status codes.
- **No DNS resolution.** Call `resolve_with_score` with the raw trimmed domain string from the request body — no UDP sockets, no upstream queries.
- **Never hold an `ArcSwap` guard across an `.await` point.** Load engine and config at the top of the handler, do all async work after dropping the guards.
- **`blocked_status_code` drives HTTP status for blocked domains.** Read it from `AppState` per-request — do not hardcode 200 or 403.

## Rules

- Max domain length is 253 characters. Return `422` for over-length input, `400` for missing or empty.
- SIGHUP and `POST /api/v1/blocklists/update` use the same reload sequence: load config → build engine → `store` config → `store` engine. Keep the current engine on failure.
- `POST /api/v1/blocklists/update` responds `202 Accepted` immediately; reload runs in a `tokio::spawn` task.

## Testing

- Unit tests in `src/routes/check.rs` — use `router().with_state(...).oneshot(request)`, no port binding.
- Integration tests in `tests/api.rs` — cover all endpoints including error paths and `blocked_status_code` variants.
- Run with `cargo nextest run -p dgaard-rest`.
