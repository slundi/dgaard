# DGAARD Stat Monitor (TUI)

A real-time telemetry viewer for your custom DNS proxy. This tool consumes binary events via a Unix Domain Socket and resolves domain hashes using a static mapping file to provide a live view of network activity without impacting proxy performance.

## How it Works

1. **Warm-up**: On startup, the monitor reads the mapping.bin file into an in-memory `BTreeMap` or `HashMap` for O(1) or O(logn) domain lookups.
2. **Streaming**: It connects to the Unix socket and parses the length-prefixed binary stream.
3. **Aggregation**: It tracks query counts, block rates, and client activity in real-time.
4. **Visualization**: Uses Ratatui to render a dashboard showing live logs and top-N statistics.

## Protocol Breakdown

The monitor parses the following wire format:

* Frame: [u16: Length][u8: Type][Payload]
* Types: 0x00 (Mapping Update) or 0x01 (Query Event).
