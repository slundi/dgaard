# DGAARD Stat Monitor (TUI)

A real-time telemetry viewer for your custom DNS proxy. This tool consumes binary events via a Unix Domain Socket and resolves domain hashes using a static mapping file to provide a live view of network activity without impacting proxy performance.

## How it Works

1. **Warm-up**: On startup, the monitor reads the mapping.bin file into an in-memory `BTreeMap` or `HashMap` for O(1) or O(logn) domain lookups.
2. **Streaming**: It connects to the Unix socket and parses the length-prefixed binary stream.
3. **Aggregation**: It tracks query counts, block rates, and client activity in real-time.
4. **Visualization**: Uses Ratatui to render a dashboard showing live logs and top-N statistics.

## Protocol Breakdown

The monitor parses the following wire format:

- Frame: [u16: Length][u8: Type][Payload]
- Types: 0x00 (Mapping Update) or 0x01 (Query Event).
- Query Event payload: [u64: timestamp][u64: domain hash][16 bytes: client IP][u8: action][extra]

| Action | Meaning                                        | Extra                                       |
| ------ | ---------------------------------------------- | ------------------------------------------- |
| 0      | Allowed                                        | —                                           |
| 1      | Proxied                                        | —                                           |
| 2      | Blocked                                        | u32 reason flags                            |
| 3      | Suspicious                                     | u32 reason flags                            |
| 4      | Highly suspicious                              | u32 reason flags                            |
| 5      | Allowed by an override                         | —                                           |
| 6      | Cached (answered from dgaard's response cache) | —                                           |
| 7      | Error (SERVFAIL)                               | u8 kind: 0 upstream failure, 1 DNSSEC bogus |

A monitor older than the dgaard it reads rejects actions 6 and 7 and keeps
reconnecting: upgrade both together. From this version on, a monitor skips
any message it does not understand instead of reconnecting.

## Quick start

```bash
cargo install dgaard-monitor

# attach to a running dgaard instance
dgaard-monitor --socket /tmp/dgaard_stats.sock --index /var/dgaard/host_mapping.bin
```
