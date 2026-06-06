# dgaard-engine

Embeddable DNS filtering and scoring library. No async runtime — suitable for DNS proxies, MTAs, HTTP services, or any Rust application that needs domain threat assessment.

## Features

- **Stratified filter pipeline**: whitelist → exact match → suffix/wildcard → heuristics → scoring
- **Suspicion scoring**: 0–10 score with per-reason breakdown (`SuspicionScore`)
- **DGA detection**: Shannon entropy and N-gram language model analysis
- **DPI lite**: TXT record entropy, CNAME cloaking detection, DNS rebinding shield, QType policy
- **Lexical analysis**: consonant clustering, IDN homograph detection, banned keyword matching
- **ASN filtering**: block autonomous systems used for malware hosting or crypto mining
- **Low-overhead lookups**: xxh64-hashed `HashMap` and Bloom filters for sub-millisecond exact-match queries

## Usage

```toml
# Cargo.toml
dgaard-engine = { path = "../dgaard-engine" }
```

```rust
use dgaard_engine::{Config, FilterEngine, resolve_with_score};

let config = Config::default();
let engine = FilterEngine::build_from_files(&config, 42u64);
let result = resolve_with_score("example.com", &engine, &config);
println!("{:?}", result.action);
```

## Public API

| Symbol                                          | Description                                                                       |
| ----------------------------------------------- | --------------------------------------------------------------------------------- |
| `Config`                                        | TOML-parsed engine configuration (`Config::load(path)` or `Config::default()`)    |
| `FilterEngine`                                  | Compiled filter state — blocklists, models, heuristics                            |
| `FilterEngine::build_from_files(&config, seed)` | Load lists from disk and build the engine                                         |
| `resolve_with_score(domain, &engine, &config)`  | Run the full pipeline; returns `ResolveResult`                                    |
| `ResolveResult`                                 | `action: Action` + `score: SuspicionScore`                                        |
| `Action`                                        | `Block(BlockReason)`, `Allow`, `ProxyToUpstream`, `Redirect(ip)`, …               |
| `BlockReason`                                   | Identifies the exact trigger: `StaticBlacklist`, `HighEntropy`, `DnsRebinding`, … |
| `SuspicionScore`                                | Cumulative 0–10 score with `reasons: Vec<BlockReason>`                            |

## Configuration Sections

| Section                | Purpose                                                                               |
| ---------------------- | ------------------------------------------------------------------------------------- |
| `[sources]`            | Paths to blacklist, whitelist, and NRD files                                          |
| `[security.structure]` | Max subdomain depth, max label/domain length, lowercase enforcement                   |
| `[security.lexical]`   | Entropy threshold, consonant ratio, N-gram model paths, banned keywords               |
| `[security.dpi]`       | TXT entropy, CNAME following depth, rebinding shield, QType policy, low-TTL threshold |
| `[tld]`                | Blocked and suspicious TLD lists                                                      |
| `[asn]`                | ASN block list                                                                        |
| `[scoring]`            | `blocking_threshold` (default 10), `log_suspicion_threshold`                          |

Full example: [`config.example.toml`](../config.example.toml)

## Build

```bash
cargo build -p dgaard-engine --release
```

## Tests

```bash
cargo nextest run -p dgaard-engine
```
