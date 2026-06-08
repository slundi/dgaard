# Roadmap

**📂 Dgaard Project Tree**

```
dgaard/
├── Cargo.toml               # Dependencies (Tokio, Trust-DNS, Postcard, etc.)
├── AGENT.md                 # Context for AI coding assistants
├── README.md                # Documentation & Quick Start
├── build.sh                 # Cross-compilation script (MIPS/ARM/musl)
├── dgaard.toml              # Default configuration file
│
├── src/
│   ├── main.rs              # Entry point, UDP loop, & Task Spawning
│   ├── config.rs            # TOML Parsing & Validation
│   ├── dns.rs               # Packet parsing & NXDOMAIN generation
│   ├── resolver.rs          # Core Logic: The "Stratified Filter" pipeline
│   ├── dga.rs               # Shannon Entropy & Lexical math
│   ├── stats.rs             # Unix Socket & Postcard serialization
│   ├── updater.rs           # Background HTTP downloader & ArcSwap logic
│   ├── abp.rs               # ABP/EasyList domain extractor
│   └── filter/
│       ├── mod.rs
│       ├── bloom.rs         # Bloom Filter implementation for NRD/Large lists
│       └── fst.rs           # Finite State Transducer for Wildcards/Suffixes
│
└── openwrt/
    ├── Makefile             # OpenWrt Package Makefile
    └── files/
        └── dgaard.init      # Procd Init script (/etc/init.d/dgaard)
```

## Phase 1: Core Runtime & Infrastructure ✅

_Focus: Getting the "Engine" to start and manage threads correctly._

- [x] 1.1. **CLI Entry**: Setup gumdrop and handle `--config` and `--version` flags.
- [x] 1.2. **Config Discovery**: Logic to check `/etc/dgaard/` then local directory for the file.
- [x] 1.3. **Configuration loader**: parse the configuration using `toml-span` and print the listen_addr.
- [x] 1.4.** Runtime Setup**: Use tokio::runtime::Builder to set thread counts based on the parsed config.
- [x] 1.5 **UDP Binding**: Bind the initial socket with `UdpSocket`.
- [x] 1.6 **Socket2 Optimization** (SO_REUSEPORT implementation): Apply set_reuse_port(true) and set_nonblocking(true) using the socket2 crate.

## Phase 2: The Parsing Engine (Source Handling)

_Focus: Converting various file formats into your internal memory format (`rkyv` or `HashSet`)._

- [x] 2.1. **Host Format Parser**: Extract `some.domain.tld` from `0.0.0.0` or `127.0.0.1` prefixes.
- [x] 2.2. **Domain List Parser**: Simple line-by-line cleaner (trimming, removing comments `#`).
- [x] 2.3. **Dnsmasq Parser**: Use a Regex or `split('/')` to extract the domain from `address=/domain/0.0.0.0`.
- [x] 2.4. **AdGuard/ABP** "Fast Path" Parser: Identify simple `||domain^` rules and "promote" them to the exact-match list to avoid the Regex engine.
- [ ] 2.5. **Archive Builder**: A commit for the logic that takes all parsed lists and serializes them into an `rkyv` Zero-Copy binary file for instant loading.
- [ ] 2.6. **Bitmask Compiler**: Extend the Archive Builder to embed the mapping between config files, their source flags, and the final `rkyv` binary identifier.

## Phase 3: The Stratified Logic (The "Funnel")

_Focus: Implementing the `Action` logic step-by-step._

- [x] 3.1. **Pipeline Orchestrator**: Create a `Resolver::resolve(&self, query)` function that loops through a `Vec<FilterStep>` (✅ `src/resolve.rs - resolve()` loops through `config.server.pipeline`).
- [x] 3.2. **Structure Gatekeeper**: Implement the max_subdomain_depth check using usize (✅ `src/resolve.rs - is_structure_invalid()` checks depth & length).
- [x] 3.3. **Whitelist Lookup**: Implement the Sorted `Vec<u64>` with binary_search() for the fastest O(logn) memory-efficient lookup or `HashSet<u64>` (using `xxh3_64`) (✅ `src/resolve.rs - is_whitelisted()` uses xxhash + `fast_map`).
- [x] 3.4. **TLD Blacklist**: Implement the exclude TLD check.
- [x] 3.5. **Static Blacklist Step**: Implement the lookup in the Bloom Filter + `rkyv` archive (✅ `src/resolve.rs - is_blocked()`).
- [x] 3.6. **Upstream Forwarder**: Implement the `ProxyToUpstream` logic using `trust-dns-proto` to send the UDP packet and wait for a response (✅ `src/dns.rs - forward_to_upstream()`).

## Phase 4: Intelligence & Heuristics

_Focus: Adding the "Brain" features that differentiate Dgaard from Pi-hole._

- [x] 4.1. **Gatekeeper** (Structure): Implement the `max_subdomain_depth` and `force_lowercase_ascii` checks (✅ was same as 3.2).
- [x] 4.2. **Shannon Entropy**: Create the `math::entropy` module to calculate randomness (✅ `src/dga.rs - calculate_entropy_fast()`).
- [x] 4.3. **Consonant Ratio**: Implement the lexical check for "unnatural" letter clustering.
- [x] 4.4. **N-Gram Loader**: Implement the binary loader for the `.bin` language models (source? https://www.unb.ca/cic/datasets/dns-2021.html).
- [x] 4.5. **Multi-Model N-Gram Logic**: Implement the "OR" logic (if domain passes English or French, it’s allowed).
- [x] 4.6. **Punycode/IDN**: Add `idna` crate integration for the "Smart IDN" mode (✅ `src/resolve.rs - is_illegal_idn()`).
- [ ] 4.7. **Forbidden words**: for a parental control, introduce the following fields:
  - in the TOML section `[security.lexical]`
    - `banned_keywords = ["porno", "casino", "drogue", "bet", "sex"]` for forbidden keywords. It will avoid a blocklist of 2 millions domains in RAM. Instead we will use `AhoCorasick` that will have few keywords.
    - `strict_keyword_matching = true` to avoid false positive and block the word with a separator: `casinon-les-bains.fr` city website will be blocked with `*casino*` and we dont want to
  - in the `[tld]` section:
    - `suspicious_tlds = [".com", ".net", ".org"]` so we block if suspicious tld and banned keywords matches
- [ ] 4.8. **Deduplication**: when loaling blocklists we can have TLD blocking and domain blocking doing the same thing. Example: coverage for blocked TLD `.xyz` will bloc domains like `bad-site.xyz` (bigger depth), wildcard `abc*.def.xyz` and regexes like `[some-regex]+\\.xyz`. To reduce RAM usage, it is required.
  - [x] check before adding a filter
  - [ ] check if the current filter is better (smaller depth) than an already existing one so we can replace it

## Phase 5: Telemetry & Monitoring

_Focus: Sharing the internal state with the outside world._

- [x] 5.1a. **StatEvent Definition**: Define the `StatEvent` struct with BlockReason.
- [ ] 5.1b. **Struct Update**: Update `StatEvent` to replace `BlockReason` (a plain enum) with a compact `u16` bitmask representing accumulated `ThreatKind` flags.
- [x] 5.2. **MPSC Channel**: Setup the `tokio::sync::mpsc` channel to pass events from the Resolver to the Stats task.
- [x] 5.3. **Unix Domain Socket** (UDS) Server: Implement the listener that streams `Postcard`-encoded events.
- [ ] 5.4. **Basic CLI Logger**: Create a small internal function that prints blocks to `stdout` (for initial debugging).
- [ ] 5.5. **Client Decoder**: Add to the CLI tool the logic to decode the bitflags received over the Unix socket into human-readable strings based on the active configuration.

## Phase 6: Reliability & Advanced Networking

_Focus: Making the proxy production-ready for SMEs._

- [x] 6.1. **IPv6 Support**: Refactor `Action` to use `IpAddr` and update the Upstream forwarder to handle `AAAA` records.
- [x] 6.2. **Upstream Fallback**: Implement a "Retry" logic if the primary DNS (e.g., `9.9.9.9`) timeouts (✅ `dns.rs`).
- [x] 6.3. **Graceful Shutdown**: Use `tokio::signal::ctrl_c` to wait for active tasks to finish before exiting (✅ `src/runtime.rs` - `ShutdownGuard` + `TaskGuard` RAII pattern).
- [x] 6.4. **Hot-Reload**: Implement a `SIGHUP` signal listener to reload the TOML config and lists without stopping the process.

## Phase 7: Bypass (extra feature)

- [ ] 7.1. **Bypass manager**: structure to handle temporary session so a time limit should be set.

```rust
struct BypassEntry {
    until: std::time::Instant,
    mode: BypassMode, // FullBypass, NoLog, DedicatedList (configuration through a special whitelist)
}

if let Some(entry) = self.bypass_map.get(&client_ip) {
    if entry.until > Instant::now() {
        // Appliquer la logique de bypass
    }
}
```

- [ ] 7.2. **Stat filtering**: Filter what data are written on the UNIX socket to match the log strategy. Do not log some domains for GDPR purposes (health website, ...) or personal (lottery, adult, ...).

```rust
pub enum LogStrategy {
    Full,       // Classic logging
    Anonymous,  // Log without client IP
    None,       // No log (Incognito)
}

pub struct StatEvent {
    pub domain: String,
    pub strategy: LogStrategy,
    // ...
}
```

- [ ] 7.3. **CLI Control**: add (with `gumdrop`) commands (`bypass TIME`, `anonymous TIME`, `incognito TIME` where time is in minutes `30m` or hours `2h`, or maybe day or week too. We should have a TOML configurable default time) to send control signals.

## Phase 8: Deep Packet Inspection (DPI Lite) & Advanced Filtering

_Focus: Analysing DNS payloads and response records._

- [x] 8.1. **Inbound Record Inspector**: logic to parse and validate answer sections (A, AAAA, TXT).
- [x] 8.2. **TXT Entropy Sentry**: calculate entropy on TXT record content to detect data exfiltration/C2 (Google SPF key or website record check may use this field sobase64 or any encrypted data will have a high entropy).
- [x] 8.3. **CNAME Unmasking**: recursive check of CNAME targets against blacklists (Cloaking defense) (ie: `track.domain.tld` is referring to `ad-server.net`).
- [x] 8.4. **DNS Rebinding Shield**: reject public queries resolving to private IP ranges (RFC 1918).
- [x] 8.5. **QType Warden**: policy-based blocking for suspicious types (NULL almost only used by DNS tunneling, HINFO for system information, ANY, etc.).
- [x] 8.6. **Low TTL**: if TTL is very low (like less than 10s but configurable) and not a known CDN (like Akamai) it should increase suspicious score.
- [ ] 8.7. **DNS Rebinding Shield (known hosted malware)**: from a list of IPs or using geoIP or known range for hosted malware.
- [x] 8.8. **ASN Filtering**: for crypto mining autonomous systems?

## Phase 9: Threat Intelligence & Analytics

_Focus: Turning raw block data into actionable insights._

- [ ] 9.1. **Lexical Trend Engine**: extract top TLDs and keywords from current blocklists to suggest parental filters.
- [ ] 9.2. **Structure Analytics**: calculate top subdomain depth and label length distribution.
- [ ] 9.3. **DGA Effectiveness Audit**: average entropy and consonant ratio of blocked vs. allowed domains.
- [ ] 9.4. **List Collision Logic**: identify domains appearing in multiple sources for 100% confidence scoring.

## Unsorted

- [ ] **Geoip blocking**: using MaxMind format (`mmdb` file). Crate `maxminddb` with `mmap` support to save RAM on OpenWRT. Only perform the test on successful DNS resolve. Add a bitflag for suspicious GEOIP.

```toml
[security.geo_ip]
enabled = true
# Path to MaxMind GeoLite2-Country.mmdb or equivalent ip2location or DB-IP
database_path = "/etc/dgaard/GeoLite2-Country.mmdb"

# List of country codes (ISO 3166-1 alpha-2) considered suspicious
suspicious_countries = ["RU", "CN", "KP", "IR"]

# Points to add SuspicionScore if response IP is in suspicious list
suspicious_country_score = 3
```

- [x] **Multi-Thread Spawn**: A loop that spawns a `tokio::spawn` task for every incoming packet (`src/runtime.rs`).
- [x] **Host index**: when building whitelists and blocklist, generate `/var/dgaard/host_mapping.bin` (or `.txt`) so external application can retrieve the domain, the list type from the xxh3_64 hash.
- [x] **Browser black/whitelist**: when parsing ABP list only put the ignored rule in another text file so the user can use it for its browser since it will mainly be CSS/JS/HTML blocking.
- [ ] **Terminal colors**: for the few printed message crates are [yansi](https://crates.io/crates/yansi) or [anstyle](https://crates.io/crates/anstyle) or custom implementation. But it will run as the daemon so the log will probably go to syslog or journald so colors chars may make the log unreadable so maybe [tracing](https://crates.io/crates/tracing) or [log](https://crates.io/crates/log) instead.

```rust
const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const RESET: &str = "\x1b[0m";

println!("{}[OK]{} Dgaard is running", GREEN, RESET);
```

- [ ] **Suspicious scoring**: block when a score is greater than 10. Start with light checks in order to avoid running entropy, ngram or other heavy processing if already over 10:
  - enthropy >4.0: +4
  - consonant clusturing >4-5 and ration vowels/consonants unbalanced
  - domain depth >= 5: +3
  - domain string very long (greater than 60 chars for example): +3
  - suspicious TLD: +3
  - low TTL: +2
  - IDN Homograph (Punycode): +6
  - NRD (Domain < 24h): +5
  - high entropy on TXT is very very very often for bad stuffs
  - DNS rebinding give the highest score: +10 (immediate blocking)
  - forbidden words + suspicious TLD: +10 (immediate blocking)
- [x] **Scoring engine**: for a scoring from 0 to ten, we can consider: 0-3 is safe, 4-6 is suspicious (so we can have full log), 7-9 is highly suspicious, 10 will block
  - [x] `blocking_threshold` so the user can configure it instead of having the hardcoded 10
  - [x] `log_suspicion_threshold` log when in the unix socket when the threshold is reaching it
- [ ] **TXT filtering**:
  - [ ] max TXT length
  - [ ] max TXT paquet per second/minute?
- [ ] **Blacklist domain stats**: from some lists perform some stats:
  - **Structure stats**
    - Top TLD that have blocked domains
    - Top words (for the parental control)
    - Top words + TLD?
    - digits at the ends of words
    - which words are on the same lists (OISD, StevenBlack, etc.). If it is on 5 lists it is safe to block.
    - **Top Subdomain Depth**: Which domains have the most labels (e.g., `a.b.c.d.e.com`)? This is a strong indicator of DNS tunneling.
    - **Length Distribution**: Do the blocks primarily involve short domains (phishing) or very long domains (data exfiltration)?
    - **Vowel/Consonant Ratio**: If your top blocked words contain a lot of `zqx`, `rtp`, this is statistical proof of your DGA engine’s effectiveness.
  - **Time-Based Statistics** (Response Time)
    - **Domain Age (NRD)**: If I can have access to the creation date (via NRD lists), extract the “Top blocked domains under 24 hours old.” (key metric for security).
    - **Blocking Frequency by Client**: Identify which machine on your local network (source IP) is attempting to access the highest number of blocked domains. This helps identify an infected PC that is “bombarding” C2 servers.
  - **List “Collision” Statistics (Overlap)**
    - **Source Effectiveness**: Which list (adaway.txt vs. malware.txt) caused the most actual blocks? Usefulness: If a list with 500,000 entries never blocks anything in a month, we can delete it to free up RAM on the router.
    - **Intersection**: Which domains appear in multiple lists? A domain appearing in 3 different lists has a 100% blocking confidence score.
  - **Advanced Lexical Analysis**
    - **Top “Typosquatting”**: Detect domains that resemble well-known brands (e.g., g00gle, paypa1) using the Levenshtein distance.
    - **Average Entropy of Blocked Domains**: What is the average entropy score of blocked domains? This will help you adjust your entropy_threshold (e.g., if all your blocks are > 4.2, you might want to lower the threshold to 4.0).
  - **Record Type** (QType)
    - **Breakdown by A vs. AAAA vs. TXT**: Are the blocks occurring on IPv4 or IPv6 requests? Note: A spike in blocked requests for **TXT** records is almost always a sign of an attempt at data exfiltration (DNS tunneling).

---

## Project: dgaard-daemon

A lightweight Unix socket daemon wrapping `dgaard-engine`. It listens for domain queries on a local socket and returns a suspicion score with reasons. Designed to integrate with external tools such as MTAs (Postfix, Rspamd), spam filters, or any process that can write to a socket.

The daemon does **not** perform DNS resolution — it evaluates the domain string only through the engine's static filters and heuristics. This makes it synchronous-friendly and suitable as a sidecar process.

**Wire protocol (per connection):**

- Input: newline-terminated UTF-8 domain string (e.g. `domaine-suspect.xyz\n`)
- Output: newline-terminated JSON object (e.g. `{"score":7,"blocked":true,"reasons":["HighEntropy","SuspiciousTld"]}\n`)
- One domain per connection (stateless, reconnect each time)

**Project tree:**

```
dgaard-daemon/
├── Cargo.toml
└── src/
    ├── main.rs          # CLI entry, config loading, socket listener loop
    ├── config.rs        # TOML config: socket_path, config_file, log level
    └── handler.rs       # Per-connection logic: parse domain, call engine, serialize response
```

### Phase D1: Project Setup

- [x] D1.1. **Workspace member**: Add `dgaard-daemon` to `Cargo.toml` workspace `members`.
- [x] D1.2. **Cargo.toml**: Declare dependencies — `dgaard-engine` (workspace), `tokio` (with `net`, `io-util`, `signal`, `macros`, `rt-multi-thread` features), `serde_json`, `serde`, `log`, `env_logger`, `argh` for CLI.
- [x] D1.3. **CLI**: Parse `--config <path>` and `--version` with `argh`. Config discovery: check `/etc/dgaard-daemon/` then current directory for `dgaard-daemon.toml`.
- [x] D1.4. **Config struct**: TOML fields — `socket_path` (default `/run/dgaard-daemon.sock`), `config_file` (path to the `dgaard-engine` config), `log_level`.
- [x] D1.5. **Engine init**: Load `dgaard_engine::Config` from the configured path, call `FilterEngine::build_from_files`, wrap both in `Arc` for sharing across tasks.

### Phase D2: Socket Listener

- [x] D2.1. **Unix socket bind**: Use `tokio::net::UnixListener::bind`. Remove stale socket file on startup if it exists. Set restrictive permissions (`0o600`) via `std::fs::set_permissions` after binding.
- [x] D2.2. **Accept loop**: `loop { listener.accept().await }` — spawn a `tokio::task` per connection, passing `Arc<FilterEngine>` and `Arc<Config>` clones.
- [x] D2.3. **Connection handler**: Read bytes until `\n` with `tokio::io::AsyncBufReadExt::read_line`. Trim whitespace. Reject empty or oversized input (max 253 bytes per RFC 1035).
- [x] D2.4. **Engine call**: Call `dgaard_engine::resolve_with_score(domain, &engine, &config)`. Serialize `ResolveResult` to JSON: `{"score": u8, "blocked": bool, "action": str, "reasons": [str]}`.
- [x] D2.5. **Write response**: Write the JSON line followed by `\n` back to the socket. Close the connection.

### Phase D3: Reliability

- [x] D3.1. **Graceful shutdown**: Listen for `SIGTERM` and `SIGINT` via `tokio::signal`. Stop accepting new connections; let in-flight tasks complete.
- [x] D3.2. **SIGHUP reload**: On `SIGHUP`, reload `dgaard_engine::Config` and rebuild `FilterEngine`, atomically swap the `Arc` with `arc-swap`.
- [x] D3.3. **Error handling**: Log malformed input and IO errors with `log::warn!`. Never crash on a bad domain string — return `{"error": "..."}` JSON line instead.

### Phase D4: Tests

- [x] D4.1. **Unit tests** (`src/handler.rs`): test JSON serialization for each `Action` variant (`Block`, `Allow`, `ProxyToUpstream`).
- [x] D4.2. **Integration test** (`tests/socket.rs`): spawn the daemon with a temp socket path, connect with `tokio::net::UnixStream`, send a known blocked domain and a clean domain, assert response fields.

---

## Project: dgaard-rest

An HTTP REST API wrapping `dgaard-engine`. Exposes domain scoring over HTTP/JSON for integration with web services, dashboards, or any tool that speaks HTTP. Uses `axum` (already in workspace deps).

**Project tree:**

```
dgaard-rest/
├── Cargo.toml
└── src/
    ├── main.rs          # CLI entry, config loading, axum router, server startup
    ├── config.rs        # TOML config: listen_addr, config_file, blocked_response_code
    ├── state.rs         # AppState: Arc<FilterEngine>, Arc<Config>
    └── routes/
        ├── mod.rs
        ├── health.rs    # GET /api/v1/health
        ├── blocklists.rs# GET + POST /api/v1/blocklists
        └── check.rs     # POST /api/v1/check
```

### Phase R1: Project Setup

- [x] R1.1. **Workspace member**: Add `dgaard-rest` to `Cargo.toml` workspace `members`.
- [x] R1.2. **Cargo.toml**: Declare dependencies — `dgaard-engine` (workspace), `tokio` (full), `axum`, `serde`, `serde_json`, `tower`, `log`, `env_logger`, `argh`.
- [x] R1.3. **CLI**: Parse `--config <path>` and `--version` with `argh`. Config discovery: check `/etc/dgaard-rest/` then current directory for `dgaard-rest.toml`.
- [x] R1.4. **Config struct**: TOML fields — `listen_addr` (default `127.0.0.1:8080`), `config_file` (path to `dgaard-engine` config), `blocked_status_code` (`200` or `403`, default `200`).
- [x] R1.5. **Engine init**: Load `dgaard_engine::Config`, call `FilterEngine::build_from_files`, store both in `AppState` behind `Arc`. Register `AppState` as axum shared state.

### Phase R2: Endpoints

- [x] R2.1. **`GET /api/v1/health`**: Return HTTP 204 No Content. No body. Used by load balancers and monitoring.
- [x] R2.2. **`GET /api/v1/blocklists`**: Return JSON array of blocklist metadata objects. Each object: `{"name": str, "last_updated": unix_timestamp_or_null, "count": u64}`. Data sourced from `FilterEngine`'s loaded list metadata.
- [x] R2.3. **`POST /api/v1/blocklists/update`**: Trigger an async blocklist refresh (reload from files on disk). Respond `202 Accepted` immediately. The reload runs in a spawned task and atomically swaps `FilterEngine` via `arc-swap` when done.
- [x] R2.4. **`POST /api/v1/check`**: Accept JSON body `{"domain": "example.com"}`. Call `resolve_with_score`. Return response body `{"domain": str, "score": u8, "blocked": bool, "action": str, "reasons": [str]}`. HTTP status code for blocked domains is controlled by `blocked_status_code` config field: `200` returns the body with `"blocked": true`; `403` returns HTTP 403 with the same body.
- [x] R2.5. **Input validation**: Reject missing or empty `domain` field with HTTP 400. Reject domains exceeding 253 characters with HTTP 422.

### Phase R3: Reliability

- [x] R3.1. **Graceful shutdown**: Use `axum::serve(...).with_graceful_shutdown(...)` wired to `SIGTERM`/`SIGINT`.
- [x] R3.2. **SIGHUP reload**: On `SIGHUP`, reload config and rebuild `FilterEngine`, atomically swap via `arc-swap` — same pattern as dgaard-daemon.
- [x] R3.3. **Error responses**: All errors return JSON body `{"error": "..."}` with appropriate HTTP status. Use an axum `IntoResponse` error type to centralize this.

### Phase R4: Tests

- [x] R4.1. **Unit tests** (`src/routes/check.rs`): test response serialization for `Block`, `Allow`, `ProxyToUpstream` actions. Test that `blocked_status_code = 403` config produces HTTP 403 for blocked domains.
- [x] R4.2. **Integration tests** (`tests/api.rs`): spin up the axum router with `tower::ServiceExt::oneshot`, send HTTP requests to each endpoint, assert status codes and JSON response shapes.
