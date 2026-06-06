# dgaard-daemon

Unix socket daemon that wraps `dgaard-engine`. Evaluates domain strings against the engine's static filters and heuristics and returns a JSON suspicion score. Does **not** perform DNS resolution.

Designed as a sidecar for MTAs (Postfix, Rspamd), spam filters, or any local process that can write to a Unix socket.

## Wire Protocol

One domain per connection — reconnect for each query (stateless).

**Input:** newline-terminated UTF-8 domain string

```
malware-c2.xyz\n
```

**Output:** newline-terminated JSON

```json
{"score":7,"blocked":true,"action":"Block(HighEntropy(4.52))","reasons":["HighEntropy(4.52)"]}\n
```

**Error responses:**

```json
{"error":"empty domain"}\n
{"error":"domain exceeds 253 bytes"}\n
```

## Configuration

Config is discovered in order: `--config <path>`, `/etc/dgaard-daemon/dgaard-daemon.toml`, `./dgaard-daemon.toml`. All fields have defaults — the daemon starts without a config file.

```toml
socket_path = "/run/dgaard-daemon.sock" # Unix socket path (created on startup)
config_file = "/etc/dgaard/dgaard.toml" # Path to the dgaard-engine config
log_level = "info" # env_logger filter string
```

## Quick Start

```bash
# Build
cargo build -p dgaard-daemon --release

# Run
dgaard-daemon --config /etc/dgaard-daemon/dgaard-daemon.toml

# Query (one-shot)
echo "malware-c2.xyz" | socat - UNIX-CONNECT:/run/dgaard-daemon.sock

# Reload blocklists without restart
kill -HUP $(pidof dgaard-daemon)
```

## Signals

| Signal               | Behaviour                                                             |
| -------------------- | --------------------------------------------------------------------- |
| `SIGINT` / `SIGTERM` | Graceful shutdown — drains in-flight connections, then exits          |
| `SIGHUP`             | Atomically reloads `dgaard-engine` config and rebuilds `FilterEngine` |

## Socket Permissions

The socket file is created with `0o600` (owner read/write only). If the calling process runs under a different UID, either run the daemon as that user or adjust permissions with `chmod` after startup.

## Tests

```bash
cargo nextest run -p dgaard-daemon
```

Integration tests in `tests/socket.rs` spin up real `UnixListener`/`UnixStream` pairs and assert JSON response shape, graceful shutdown, and atomic config-swap behaviour.
