# dgaard-rest

HTTP REST API that wraps `dgaard-engine`. Exposes domain scoring over HTTP/JSON for dashboards, web services, or any tool that speaks HTTP. Does **not** perform DNS resolution.

## Endpoints

### `GET /api/v1/health`

Liveness probe. Returns `204 No Content`. Used by load balancers and monitoring.

### `GET /api/v1/blocklists`

Returns metadata for all configured blocklist and whitelist files.

```json
[
  { "name": "/etc/dgaard/adaway.txt", "last_updated": 1748000000, "count": 42000 },
  { "name": "/etc/dgaard/whitelist.txt", "last_updated": 1748000001, "count": 12 }
]
```

`last_updated` is a Unix timestamp derived from the file's mtime, or `null` if unavailable. `count` is the number of non-empty, non-comment lines.

### `POST /api/v1/blocklists/update`

Triggers an async reload of blocklists from disk. Returns `202 Accepted` immediately. The engine is rebuilt in a background task and swapped atomically via `arc-swap`.

### `POST /api/v1/check`

Score a domain through the engine.

**Request:**

```json
{ "domain": "example.com" }
```

**Response:**

```json
{
  "domain": "example.com",
  "score": 0,
  "blocked": false,
  "action": "ProxyToUpstream",
  "reasons": []
}
```

**Error responses:**

| Condition                                    | Status | Body                                        |
| -------------------------------------------- | ------ | ------------------------------------------- |
| Missing or empty `domain`                    | `400`  | `{"error":"missing or empty domain"}`       |
| `domain` longer than 253 characters          | `422`  | `{"error":"domain exceeds 253 characters"}` |
| Blocked domain + `blocked_status_code = 403` | `403`  | full check response                         |

## Configuration

Config is discovered in order: `--config <path>`, `/etc/dgaard-rest/dgaard-rest.toml`, `./dgaard-rest.toml`. All fields have defaults — the server starts without a config file.

```toml
listen_addr = "127.0.0.1:8080" # TCP bind address
config_file = "/etc/dgaard/dgaard.toml" # Path to the dgaard-engine config
log_level = "info" # env_logger filter string
blocked_status_code = 200 # 200 or 403 for blocked domains
```

## Quick Start

```bash
# Build
cargo build -p dgaard-rest --release

# Run
dgaard-rest --config /etc/dgaard-rest/dgaard-rest.toml

# Check a domain
curl -s -X POST http://127.0.0.1:8080/api/v1/check \
  -H 'Content-Type: application/json' \
  -d '{"domain":"malware-c2.xyz"}'

# Health check
curl -si http://127.0.0.1:8080/api/v1/health

# Reload blocklists without restart
kill -HUP $(pidof dgaard-rest)
```

## Signals

| Signal               | Behaviour                                                             |
| -------------------- | --------------------------------------------------------------------- |
| `SIGINT` / `SIGTERM` | Graceful shutdown via `axum::serve(...).with_graceful_shutdown(...)`  |
| `SIGHUP`             | Atomically reloads `dgaard-engine` config and rebuilds `FilterEngine` |

## Tests

```bash
cargo nextest run -p dgaard-rest
```

Integration tests in `tests/api.rs` use `tower::ServiceExt::oneshot` to exercise each endpoint without binding a port.
