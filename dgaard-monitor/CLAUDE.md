# 🛰️ Telemetry Agent (DNS Monitor Service)

The Telemetry Agent is a high-performance middleware designed to consume raw binary events from the DNS Proxy, enrich them with domain metadata, and route them to various sinks (TUI, SQLite, and External APIs).

## 🏗️ Architecture Overview

The agent operates as a multi-threaded pipeline to ensure that slow disk I/O (SQLite) or network latency (SOAR/Webhooks) never blocks the ingestion of UDP DNS traffic.
Core Components

1. Ingestor: Listens on the Unix Domain Socket. Decodes the length-prefixed binary protocol.
2. Mapper: Maintains an in-memory `BTreeMap<u64, String>` loaded from the host index file. Watches the file for updates using `inotify`.
3. Dispatcher: Routes enriched events to configured sinks based on severity or action.
4. Storage Engine: A SQLite instance running in WAL (Write-Ahead Logging) mode for local historical analysis.

## 📊 Data Flow & Bitflags

To support complex security analysis, the agent treats `StatBlockReason` as a bitmask. This allows a single query to be flagged for multiple violations (e.g., a domain that is both a Newly Registered Domain and has High Entropy).

### Event Enrichment Logic

When an event arrives:

1. **Lookup**: `domain_hash` → `domain_name` (via host index).
2. **Bitmask Decoding**: u16 reasons → Human-readable labels.
3. **Severity Scoring**: * `Allowed` -> Info
    * `Suspicious` -> Warning
    * `Blocked` -> Alert

## 💾 Storage Strategy (SQLite)

The agent maintains two tiers of data to balance visibility with disk usage:

### Tier 1: The Rolling Log (`dns_events`)

Stores every single query.

* **Retention**: 24–72 hours (configurable).
* **Purpose**: Detailed forensics and the TUI "Live Feed."

### Tier 2: Hourly Aggregates (`dns_stats_hourly`)

Stores pre-computed counts: (`hour, domain_hash, client_ip, action_bits, count`).

* **Retention**: 30–90 days.
* **Purpose**: Long-term trend charts and "Top 10" reports.

## 🚀 Integration Hooks (SOAR / Webhooks)

The agent supports real-time triggers. You can define rules in `agent.toml`:

```toml
[[hooks]]
name = "Malware Alert"
trigger_on = "Blocked"
filter_reasons = ["StaticBlacklist", "CnameCloaking"]
endpoint = "https://soar.internal/api/v1/dns-alert"
method = "POST"
```

## 🛠️ Implementation Roadmap (Agent Specific)

* [ ] Asynchronous Runtime: Use `tokio` for non-blocking socket handling.
* [ ] Graceful Shutdown: Ensure the SQLite WAL is checkpointed and the Unix Socket is cleaned up on `SIGTERM`.
* [ ] Backpressure: Implement a bounded mpsc channel. If the DB or Webhook sinks fall behind, the agent should drop the oldest events rather than crashing the proxy.
* [ ] Self-Monitoring: The agent should export its own metrics (e.g., `events_processed_total`, `buffer_usage_percent`).

## 🏃 Running the Agent

```bash
# As a TUI (Standard):
./dns-monitor --socket /tmp/dns.sock --index /var/lib/dns/hosts.bin

# As a Headless Service (Enterprise/SME):
./dns-monitor --headless --db ./stats.db --forward-to http://elastic:9200
```
