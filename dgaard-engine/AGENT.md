# Agent Instructions: dgaard-engine

You are working on **dgaard-engine**, the embeddable filtering core shared by `dgaard`, `dgaard-daemon`, and `dgaard-rest`. This crate is a pure computation library with no async runtime and no networking.

## Architectural Constraints

- **No `tokio` or async code.** All public functions are synchronous. The library is called from async executors and from synchronous contexts alike — do not introduce a runtime dependency.
- **No networking.** `FilterEngine` never sends DNS queries. Domains are evaluated in isolation as raw strings.
- **Memory first.** Avoid heap allocation in the hot path. Use `Arc<str>`, `Cow<str>`, and pre-hashed `u64` lookups instead of `String` clones.
- **Fail fast.** Run cheap checks before expensive ones. The pipeline order must be respected — see Logic Order below.

## Data Structures

| Structure                    | Purpose                                                                                              |
| ---------------------------- | ---------------------------------------------------------------------------------------------------- |
| `fast_map: HashMap<u64, u8>` | O(1) exact domain lookup by xxh64 hash; the flag byte encodes `WHITELIST`, `BLOCKLIST`, etc.         |
| `bloom: BloomFilter`         | Probabilistic pre-filter for large blocklists — fast false-negative-free "is it even worth hashing?" |
| `fst: FST`                   | Finite state transducer over reversed domains for efficient suffix/wildcard matching                 |
| `aho: AhoCorasick`           | Multi-pattern keyword scan for `banned_keywords` (parental control)                                  |

## Logic Order (per query in `resolve_with_score`)

1. **Structure gatekeeper** — `max_subdomain_depth`, `max_domain_length`, `force_lowercase_ascii`. Cheapest check; drop malformed/tunnel-shaped domains immediately.
2. **Whitelist** — xxh64 hash lookup in `fast_map` with `WHITELIST` flag. Short-circuits the entire pipeline.
3. **TLD exclusion** — exact TLD string match against `config.tld.blocked`.
4. **Static blocklist** — Bloom filter pre-check then `fast_map` hash lookup.
5. **ABP / wildcard rules** — FST suffix match against reversed domain labels.
6. **Heuristics** — entropy, consonant ratio, N-gram, IDN homograph, NRD list, keyword scan. Accumulate into `SuspicionScore`.
7. **DPI checks** — TXT entropy, CNAME chain, rebinding (RFC 1918 response IPs), QType policy, ASN block, low TTL. Also accumulate score.
8. **Scoring decision** — if `score.total >= config.scoring.blocking_threshold` → `Block(Suspicious)`.

## Scoring

`SuspicionScore` accumulates points and reasons throughout the pipeline. The engine does **not** stop accumulating reasons after a block — callers receive the full picture. The `blocking_threshold` is user-configurable (default 10).

## Hash Endianness

xxh64 hashes are written and read with `XxHash64::oneshot(seed, bytes)`. Always use the seed from `FilterEngine.seed`. On big-endian MIPS targets the byte order of the input matters — operate on the raw UTF-8 bytes of the domain string, never on `u64` literals.

## Testing

- Unit tests live in the same `.rs` file as the code under test.
- Integration tests are in `tests/`.
- Run with `cargo nextest run -p dgaard-engine`.
- Coverage target: 85% (`just coverage-check`).
- Every new filter variant must have at least one unit test covering the happy path and one covering the rejection path.

## Target Environment

- **Architectures**: MIPS (big-endian OpenWrt routers), ARM, x86_64
- **RAM budget**: under 20 MB for 100 k blocked domains
- **Binary budget**: under 5 MB stripped — every new dependency must be justified
