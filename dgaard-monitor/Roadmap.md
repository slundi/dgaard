# Roadmap

## Phase 1: Foundation

* [x] **CLI Parsing**: Implement using `gumdrop` for clean argument handling (e.g., `--socket /tmp/dns.sock --index /var/lib/dns/hosts.bin --db /var/dgaard/stats.sqlite`) in `cli.rs` for future commands (default will run tui, but later `serve` for a JSON API, `websocket`, `hook`)
* [x] **Error handling**: with thiserror in `error.rs`
* [x] **App configuration**: in config.rs
* [x] **IO Layer**:
  * [x] **Binary-safe reader** for the host index file.
  * [x] **Unix Domain Socket listener** with `tokio::net::UnixStream`.
* [x] **State Management**: Create a thread-safe AppState to store rolling window statistics and the domain map.
* [x] **TOML configuration**: for inputs (socket & bin mapping file), TUI (tick, key bindings), output/integrations (sqlite file, websocket, REST API, hooks)

## Phase 2: TUI Implementation (Ratatui)

* [ ] Main Loop: Setup terminal raw mode and tick rate (e.g., 250ms).
* [ ] Input Handling: Support `q` or `Ctrl+c` to quit and `c` to clear current session stats in a separete file since we will support custom key mapping later.
* [ ] TUI layout:
  * [ ] Top bar, with 3 rowws:
   * [ ] Row 1 Header: contain tabs `Dashboard`, `Queries`, `Talkers`, `Timelines`, `About`. And some state indicator (active filter 🕵, frozen view ❄️, connectivity status)
   * [ ] Row 2 Key metrics:  total, blocked %, active client count, QPS
   * [ ] Row 3 dynamic: Split horizontally between "Live Feed" (Left 60%) and "Flag Distribution" (Right 40%)
  * [ ] remaining space is to display tab content
* [ ] `Dashboard` tab:
  * [ ] Total stats: total queries, active clients, blocked queries, percentage blocked, query types (A (IPv4), AAAA (IPv6), PTR, TXT, ...), ~~upstream server~~
  * [ ] Live Feed: A scrolling list of the last 20 queries (Client IP -> Domain -> Action).
  * [ ] Top domains: A bar chart or table of domains, red for blocked, green for permitted ones.
  * [ ] Traffic Gauge: Queries per second (QPS).
  * [ ] Most active blocking flags (count and ratio)?
* [ ] Flag Distribution: Use a Sparkline or BarChart to show which StatBlockReason bitflags are firing most often.
* [ ] Tab `Queries` (tail like) with column display: datetime, Domain, IP, blocking flags. `f` to filter flags or client, `s` for a sorting (default last queries on top) popup, `z` to freeze so the display is not updated (show info on ).
  * [ ] Implement Virtual Scrolling (only render what’s visible) to handle a history buffer of 1,000+ entries without lag.
  * [ ] Action Styling: Full row highlight or prefix icons (e.g., ✔ for Allowed, ✘ for Blocked).
* [ ] Tab `Talkers` (most active client IPs) with column display: Client or name, DNS request count, per filter count, first/last seen
  * [ ] Add Reverse DNS: If the monitor can resolve local IPs to hostnames, display the hostname in the Talker tab.
  * [ ] Popup `Talker`: Title `Talker <client>` that displays most visited domain, last domain
  * [ ] Add timeline?
* [ ] Tab `Timelines` for 24h trends: Total queries, Client activity
* [ ] Tab `About`: contains project name, version, repo URL, license, key mapping

## Phase 3: Analytics

* [ ] **Client Tracking**: Identify "Top Talkers" (most active client IPs).
* [ ] **Reason Breakdown**: If StatAction includes specific block reasons (Malware, Ad, Tracking), display a pie chart of block categories.
* [ ] **Search/Filter**: Allow filtering the live feed by specific client IP or domain keyword.

## Phase 4: Data & Persistence

* [ ] **File Watcher**: Implement notify to hot-reload the host index without restarting the monitor.
* [ ] **Timeseries DB**: Integrate SQLite (via rusqlite) to store aggregated hourly counts for top domains.
* [ ] **Hash Reconciliation**: Logic to handle index updates where a domain's hash might have changed.

## Phase 5: API & Connectivity

* [x] Headless Mode: CLI flag --headless to disable TUI and only run the API.
* [ ] JSON API: Endpoints for /stats/top-blocked and /stats/clients.
* [ ] WebSocket Stream: Mirror the Unix socket events as JSON over WebSockets for web-based GUIs.

## Phase 6: Integrations

* [ ] Action Hooks: Configuration file to define on_block triggers.
* [ ] Generic Webhooks: Support for POSTing JSON payloads to external URLs (SOAR, Slack, etc.).

## Ideas

* **Workflow**:
  1. **Detect** change via `inotify` (Linux).
  2. **Read** the new file into a *new* temporary `HashMap`.
  3. **Swap** the old map for the new one using an `Arc<RwLock<T>>` or an `AtomicPtr`.
  4. Log the reload: New index loaded: `45,000` domains mapped.
* **"Top Talkers" Table**: Instead of just showing the last resolved domain, keep a counter of queries per `client_ip`. It helps identify misconfigured devices or potential botnet activity on the network.
* **Block Ratio Gauge**: A circular or horizontal gauge showing: $Block Ratio = \frac{Total Queries Total}{Blocked Queries})​×100$. Instant visual feedback on how "aggressive" filter lists are acting.
* **Latency/Trend Sparkline**: Even though the current protocol doesn't include "Response Time," we can track Queries Per Second (QPS) over the last 60 seconds. We will visualize traffic spikes or sudden drops in network usage.
* **Interactive Lookup**: Since we have the mapping file loaded, add a "Search" mode (press `/`) where the user can type a domain to see its hash or check if it’s currently in the proxy’s index.
* **Beaconing detection**: Show domains that are periodically pinged by client.
* **Color-Coded Actions**: Using Ratatui's styling to color the live feed:
  * Green: Allowed/Resolved.
  * Red: Blocked (Malware/Ads).
  * Yellow: Special handling (e.g., Rewritten/Local DNS).
* **Domain Aging**: strategy to prevent data from becoming "stale" or misleadingly cluttered by old activity. Without aging, a domain that was queried 1,000 times a week ago would still show up as "Top Domain" today, even if it hasn't been touched since.
  * **In-Memory Aging (The "Sliding Window")**: This is most common . We only keep events that occurred within a specific timeframe (e.g., the last 60 minutes). How it works: We store events in a `VecDeque`. Every time a new event comes in, we check the timestamp of the oldest event. If it’s older than 60 minutes, we pop_front() it. Result: Our "Top Blocked" list is always a "Top Blocked in the last hour."
```rust
use std::collections::VecDeque;
use std::time::{Duration, Instant};

struct WindowedStats {
    events: VecDeque<(Instant, u64)>, // (Time, Hash)
    window_duration: Duration,
}

impl WindowedStats {
    fn add_event(&mut self, hash: u64) {
        let now = Instant::now();
        self.events.push_back((now, hash));
        
        // "Age out" old data
        while let Some((timestamp, _)) = self.events.front() {
            if now.duration_since(*timestamp) > self.window_duration {
                self.events.pop_front();
            } else {
                break;
            }
        }
    }
}
```
  * **Weighted Decay (The "Half-Life" Method)**: Instead of deleting data, we reduce its "weight" over time. Every hour, we multiply all your counters by 0.5. Result: Recent activity is heavily weighted, but consistent long-term patterns still show up. This is great for identifying "low and slow" data exfiltration.
  * **Database Partitioning (The "Bucket" Method)**: store counts in 5-minute or 1-hour chunks (buckets). Result: When we want to see "Today's stats," the app sums up the last 24 buckets. When a bucket is 30 days old, the server automatically deletes (purges) it to save disk space.

## Wonders

* Use [lnav](https://lnav.org/): for a Kibana of the terminal. So write JSON to stdout. (last queries and ad-hoc analysis)
* Use [Dashbrew](https://rasjonell.github.io/dashbrew/): TUI dashboard builder specifically designed to visualize data from scripts and APIs. So JSON genration here too.
* Use [GoAccess](https://goaccess.io/): While primarily built for web logs (Nginx/Apache), it is a highly optimized real-time visualizer. Write data in log format. https://goaccess.io/man#custom-log (talkers, top domains)
* https://github.com/dimonomid/nerdlog
* https://wtfutil.com/
* https://logdy.dev/
* https://github.com/fedexist/grafatui need to export to prometeus (Visualizing QPS, Block Ratios, and Time-series data)
