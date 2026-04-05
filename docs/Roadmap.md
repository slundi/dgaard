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

*Focus: Getting the "Engine" to start and manage threads correctly.*

* [x] 1.1. **CLI Entry**: Setup gumdrop and handle `--config` and `--version` flags.
* [x] 1.2. **Config Discovery**: Logic to check `/etc/dgaard/` then local directory for the file.
* [x] 1.3. **Congiguration loader**: parse the configuration using `toml-span` and print the listen_addr.
* [x] 1.4.** Runtime Setup**: Use tokio::runtime::Builder to set thread counts based on the parsed config.
* [x] 1.5 **UDP Binding**: Bind the initial socket with `UdpSocket`.
* [x] 1.6 **Socket2 Optimization** (SO_REUSEPORT implementation): Apply set_reuse_port(true) and set_nonblocking(true) using the socket2 crate.

## Phase 2: The Parsing Engine (Source Handling)

*Focus: Converting various file formats into your internal memory format (`rkyv` or `HashSet`).*

* [x] 2.1. **Host Format Parser**: Extract `some.domain.tld` from `0.0.0.0` or `127.0.0.1` prefixes.
* [x] 2.2. **Domain List Parser**: Simple line-by-line cleaner (trimming, removing comments `#`).
* [x] 2.3. **Dnsmasq Parser**: Use a Regex or `split('/')` to extract the domain from `address=/domain/0.0.0.0`.
* [x] 2.4. **AdGuard/ABP** "Fast Path" Parser: Identify simple `||domain^` rules and "promote" them to the exact-match list to avoid the Regex engine.
* [ ] 2.5. **Archive Builder**: A commit for the logic that takes all parsed lists and serializes them into an `rkyv` Zero-Copy binary file for instant loading.

## Phase 3: The Stratified Logic (The "Funnel")

*Focus: Implementing the `Action` logic step-by-step.*

* [x] 3.1. **Pipeline Orchestrator**: Create a `Resolver::resolve(&self, query)` function that loops through a `Vec<FilterStep>` (✅ `src/resolve.rs - resolve()` loops through `config.server.pipeline`).
* [x] 3.2. **Structure Gatekeeper**: Implement the max_subdomain_depth check using usize (✅ `src/resolve.rs - is_structure_invalid()` checks depth & length).
* [x] 3.3. **Whitelist Lookup**: Implement the Sorted `Vec<u64>` with binary_search() for the fastest O(logn) memory-efficient lookup or `HashSet<u64>` (using `xxh3_64`) (✅ `src/resolve.rs - is_whitelisted()` uses xxhash + `fast_map`).
* [x] 3.4. **TLD Blacklist**: Implement the exclude TLD check.
* [x] 3.5. **Static Blacklist Step**: Implement the lookup in the Bloom Filter + `rkyv` archive (✅ `src/resolve.rs - is_blocked()`).
* [x] 3.6. **Upstream Forwarder**: Implement the `ProxyToUpstream` logic using `trust-dns-proto` to send the UDP packet and wait for a response (✅ `src/dns.rs - forward_to_upstream()`).

## Phase 4: Intelligence & Heuristics

*Focus: Adding the "Brain" features that differentiate Dgaard from Pi-hole.*

* [x] 4.1. **Gatekeeper** (Structure): Implement the `max_subdomain_depth` and `force_lowercase_ascii` checks (✅ was same as 3.2).
* [x] 4.2. **Shannon Entropy**: Create the `math::entropy` module to calculate randomness (✅ `src/dga.rs - calculate_entropy_fast()`).
* [ ] 4.3. **Consonant Ratio**: Implement the lexical check for "unnatural" letter clustering.
* [ ] 4.4. **N-Gram Loader**: Implement the binary loader for the `.bin` language models (source? https://www.unb.ca/cic/datasets/dns-2021.html).
* [ ] 4.5. **Multi-Model N-Gram Logic**: Implement the "OR" logic (if domain passes English or French, it’s allowed).
* [x] 4.6. **Punycode/IDN**: Add `idna` crate integration for the "Smart IDN" mode (✅ `src/resolve.rs - is_illegal_idn()`).

## Phase 5: Telemetry & Monitoring

*Focus: Sharing the internal state with the outside world.*

* [ ] 5.1. **StatEvent Definition**: Define the `StatEvent` struct with BlockReason.
* [ ] 5.2. **MPSC Channel**: Setup the `tokio::sync::mpsc` channel to pass events from the Resolver to the Stats task.
* [ ] 5.3. **Unix Domain Socket** (UDS) Server: Implement the listener that streams `Postcard`-encoded events.
* [ ] 5.4. **Basic CLI Logger**: Create a small internal function that prints blocks to `stdout` (for initial debugging).

## Phase 6: Reliability & Advanced Networking

*Focus: Making the proxy production-ready for SMEs.*

* [ ] 6.1. **IPv6 Support**: Refactor `Action` to use `IpAddr` and update the Upstream forwarder to handle `AAAA` records.
* [x] 6.2. **Upstream Fallback**: Implement a "Retry" logic if the primary DNS (e.g., `9.9.9.9`) timeouts (✅ `dns.rs`).
* [ ] 6.3. **Graceful Shutdown**: Use `tokio::signal::ctrl_c` to wait for active tasks to finish before exiting.
* [ ] 6.4. **Hot-Reload**: Implement a `SIGHUP` signal listener to reload the TOML config and lists without stopping the process.

## Phase 7: Bypass (extra feature)

* [ ] 7.1. **Bypass manager**: structure to handle temporary session so a time limit should be set.
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
* [ ] 7.2. **Stat filtering**: Filter what data are written on the UNIX socket to match the log strategy. Do not log some domains for GDPR purposes (health website, ...) or personnal (lottery, adult, ...).
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
* [ ] 7.3. **CLI Control**: add (with `gumdrop`) commands (`bypass TIME`, `anonymous TIME`, `incognito TIME` where time is in minutes `30m` or  hours `2h`, or maybe day or week too. We should have a TOML configurable default time) to send control signals.

## Unsorted

* [x] **Multi-Thread Spawn**: A loop that spawns a `tokio::spawn` task for every incoming packet (`src/runtime.rs`).
* [ ] **Host index**: when building whitelists and blocklist, generate `/var/dgaard/host_mapping.bin` (or `.txt`) so external application can retrieve the domain, the list type from the xxh3_64 hash.
* [ ] **Browser black/whitelist**: when parsing ABP list put the ignored rule in another text file so the user can use it for its browser since it will mainly be CSS/JS/HTML blocking.
* [ ] **Terminal colors**: for the few printed message crates are [yansi](https://crates.io/crates/yansi) or [anstyle](https://crates.io/crates/anstyle) or custom implementation. But it will run as the daemon so the log will probably go to syslog or journald so colors chars may make the log unreadable so maybe [tracing](https://crates.io/crates/tracing) or [log](https://crates.io/crates/log) instead.
```rust
const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const RESET: &str = "\x1b[0m";

println!("{}[OK]{} Dgaard is running", GREEN, RESET);
```
