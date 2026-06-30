# Recursive DNS Resolver — Design & Roadmap

## Goals

- Add a **recursive resolution mode** where dgaard iterates the delegation chain from root hints itself, eliminating dependency on an external upstream resolver.
- Retain the existing **forwarder mode** (renamed from `[upstream]` to `[forwarder]`).
- Track domain **popularity** across both modes for adaptive cache management and prefetch priming.
- **Prefetch** hot domains before their TTL expires, eliminating latency spikes for frequent queries.
- **Persist** popularity scores across restarts so the tracker regains accuracy quickly after a reboot.

---

## TOML Configuration Changes

### `[server]`

New field `mode` selects the resolution backend:

```toml
[server]
mode = "recursive" # "recursive" | "forwarder"
```

### `[forwarder]` — replaces `[upstream]`

**Hard rename**: `[upstream]` is removed; the parser rejects it with a clear error and a pointer to the CHANGELOG. Old configs must be updated by the operator before upgrade. No alias period.

Semantics are identical to the previous `[upstream]` block; only the key name changes.

```toml
[forwarder]
servers = ["1.1.1.1:53", "9.9.9.9:53"]
timeout_ms = 2000
use_0x20_randomization = true
```

### `[recursive]`

```toml
[recursive]
# Root hints file (BIND-style). Falls back to compiled-in defaults if absent or not set.
# root_hints_path = "/etc/dgaard/root.hints"

# Hard ceiling on delegation hops. Primary loop protection is the visited-zone set
# (see algorithm); this is a fallback for non-repeating but pathologically deep chains.
# BIND default: 7, Unbound default: 11. Real-world maximum: ~6 hops.
max_delegation_depth = 8

# Maximum total upstream queries per top-level client resolution. Defence in depth on
# top of cycle detection: caps NS-name fanout amplification across all sub-resolves
# (CNAME chase + out-of-zone NS lookups). Cost on hot path: one u32 += 1 per query.
max_queries_per_resolution = 64

# Maximum CNAME chain length before returning SERVFAIL.
max_cname_depth = 10

# Per-nameserver UDP query timeout (ms). TCP fallback reuses the same value.
query_timeout_ms = 3000

# QNAME minimization (RFC 9156). Send minimal QNAME at each delegation hop instead
# of the full domain. Standard practice in modern recursive resolvers.
qname_minimization = true

# Strict bailiwick policy. When true (default), any referral pointing outside the
# current zone returns SERVFAIL immediately. When false, the resolver tries the next
# ns_addr; if all NSes give bad referrals, SERVFAIL. False is more tolerant of
# misconfigured zones.
strict_bailiwick = true

# Nameserver query concurrency policy.
# "sequential": try each ns_addr in order; on timeout/error, move to next.
# "staggered":  launch up to max_concurrent_queries spaced by ns_stagger_ms.
# "parallel":   race up to max_concurrent_queries simultaneously (highest upstream load).
ns_concurrency = "sequential"
max_concurrent_queries = 2 # used by staggered (extra launches) and parallel (total)
ns_stagger_ms = 200 # gap between staggered launches

# Advertise EDNS0 OPT record on outgoing queries (RFC 6891). Required for modern
# authoritatives. Buffer size 1232 avoids IP fragmentation per DNS Flag Day 2020.
edns0_enabled = true
edns0_udp_payload_size = 1232

# Top-N most popular domains persisted to disk (by effective_score at save time).
save_top_domains = 2048

# Path for the popularity snapshot (rkyv binary; see Persistence section).
save_path = "/var/dgaard/top-domains.bin"

# How often the popularity snapshot is written to disk (seconds).
# 1m = 60, 10m = 600, 1h = 3600.
save_interval_secs = 600

# Popularity score half-life in seconds. Score halves every N seconds via bit-shift
# at read time. No background task required.
# Examples: 1h = 3600, 24h = 86400, 1 week = 604800.
decay_half_life_secs = 86400
```

### `[prefetch]`

Applicable in both modes (forwarder and recursive).

```toml
[prefetch]
enabled = true

# Minimum gap between consecutive prefetch queries (ms). Smooths CPU load.
interval_ms = 200

# Bounded mpsc channel capacity. Excess prefetch requests are silently dropped.
queue_capacity = 256

# Trigger prefetch when remaining TTL drops below this threshold (seconds).
ttl_remaining_trigger_secs = 30
```

---

## Architecture

### Resolver abstraction — `UpstreamResolver` trait

`handle_query` receives an `Arc<dyn UpstreamResolver>` initialised once at startup from the configured `mode`. No `if mode` branching inside the hot query path.

The trait accepts a **parsed `DnsPacket`** rather than raw bytes. Rationale: `handle_query` already parses the incoming packet to extract qname/qtype; passing the parsed form down means `RecursiveResolver` does not re-parse, and the prefetch worker does not synthesise wire-format packets just for the trait.

```rust
pub trait UpstreamResolver: Send + Sync {
    /// Resolve a parsed DNS query and return the raw wire-format DNS response.
    async fn resolve(&self, query: &DnsPacket) -> std::io::Result<Vec<u8>>;
}

pub struct ForwardingResolver { /* existing socket pool + upstream selection */ }
pub struct RecursiveResolver  { /* iterative delegation loop, see below */    }
```

Both implementations live under `dgaard/src/dns/`. `main.rs` constructs the concrete type, boxes it, and stores it in a `OnceLock<Arc<dyn UpstreamResolver>>`.

Post-resolution filters (DPI, DNSSEC, rebinding shield, response scoring) are applied identically to the bytes returned by either implementation — they do not change.

---

### Iterative resolution algorithm (`RecursiveResolver`)

Uses `hickory-proto` (already in the workspace via `hickory-resolver`) for DNS wire-format encoding/decoding. No additional crate is required.

**State threaded through the resolve loop** (and through every recursive sub-call — CNAME chase, out-of-zone NS lookup):

| Variable         | Type       | Purpose                                                                                                      |
| ---------------- | ---------- | ------------------------------------------------------------------------------------------------------------ |
| `visited_zones`  | `Vec<u64>` | xxh3_64(lowercase zone) for each zone delegated through; rejects delegation cycles                           |
| `visited_cnames` | `Vec<u64>` | xxh3_64(lowercase CNAME target) for each chain hop; rejects CNAME cycles                                     |
| `depth`          | `u8`       | Delegation hops in the _current_ sub-loop; reset to 0 per CNAME follow; capped at `max_delegation_depth`     |
| `queries_used`   | `u32`      | Total upstream UDP/TCP queries across the whole top-level resolution; capped at `max_queries_per_resolution` |

```
resolve(domain, qtype, &mut visited_zones, &mut visited_cnames, &mut queries_used)
  -> Result<Vec<u8>>:

  ns_addrs = select_random(root_hints, count=3)
  zone     = "."
  depth    = 0

  loop:
    if queries_used >= max_queries_per_resolution: return SERVFAIL
    if depth        >= max_delegation_depth:       return SERVFAIL

    queries_used += 1
    response = query_any(ns_addrs, domain, qtype, timeout, ns_concurrency)

    match response:
      ANSWER (rcode=NOERROR, answer non-empty):
        if answer contains CNAME and qtype != CNAME:
          if visited_cnames.len() >= max_cname_depth: return SERVFAIL
          target = extract_cname_target(answer)
          target_hash = xxh3_64(lowercase(target))
          if visited_cnames.contains(target_hash): return SERVFAIL   // CNAME cycle
          visited_cnames.push(target_hash)
          return resolve(target, qtype, visited_zones, visited_cnames, queries_used)
        return response

      REFERRAL (rcode=NOERROR, answer empty, authority has NS records):
        new_zone = extract_zone_from_authority(response)

        // Bailiwick check: referral must narrow the zone, never widen it.
        if not new_zone.is_subdomain_of(zone):
          if strict_bailiwick:
            return SERVFAIL
          else:
            // Lenient mode: discard the bad referral, try the next ns_addr.
            // If all NSes give bad referrals, fall through to SERVFAIL.
            log_warn("out-of-bailiwick referral from " + current_ns)
            advance_to_next_ns_addr_or_servfail()
            continue

        // Cycle detection: reject any zone we have already delegated through.
        zone_hash = xxh3_64(lowercase(new_zone))
        if visited_zones.contains(zone_hash): return SERVFAIL
        visited_zones.push(zone_hash)

        ns_names = extract_ns_names(response.authority)

        // Prefer glue (A/AAAA in additional section). Only accept glue for NS names
        // that are IN-BAILIWICK relative to new_zone. Out-of-bailiwick glue is a
        // classic cache-poisoning vector (CVE-2008-1447 family); discard it.
        glue = extract_in_bailiwick_glue(response.additional, ns_names, new_zone)
        if glue is not empty:
          ns_addrs = glue
        else:
          // Out-of-zone NS: resolve each NS name's address.
          // The recursive resolve_ns_addresses shares visited_zones, visited_cnames,
          // and queries_used so it cannot blow the budget allocated to this client query.
          ns_addrs = resolve_ns_addresses(ns_names, visited_zones, visited_cnames, queries_used)
          if ns_addrs is empty: return SERVFAIL

        zone   = new_zone
        depth += 1

      NXDOMAIN:
        return NXDOMAIN

      SERVFAIL | timeout | error:
        return SERVFAIL   // all tried ns_addrs failed
```

**Key correctness properties:**

| Property                      | Mechanism                                                                                                                                                               |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Delegation cycle detection    | `visited_zones: Vec<u64>` of `xxh3_64(zone)`; linear scan, ≤ `max_delegation_depth` entries; threaded into sub-resolves                                                 |
| CNAME cycle detection         | `visited_cnames: Vec<u64>` of `xxh3_64(target)`; threaded across CNAME-follow recursion (the original spec's bug: previously per-chain only inside one resolve() frame) |
| Delegation depth cap          | `depth >= max_delegation_depth` (default 8) — fallback for non-repeating deep chains                                                                                    |
| Query amplification cap       | `queries_used >= max_queries_per_resolution` (default 64) — defence in depth over cycle + depth checks; one u32 += 1 per upstream query                                 |
| Bailiwick enforcement         | Referral zone must be subdomain of current zone. Strict (SERVFAIL on first bad referral) or lenient (try next ns_addr) per `strict_bailiwick`                           |
| In-bailiwick glue             | Glue A/AAAA records only accepted for NS names inside `new_zone`. Out-of-bailiwick glue is discarded silently                                                           |
| Out-of-zone NS resolution     | `resolve_ns_addresses` shares the same `visited_zones`, `visited_cnames`, `queries_used` so it cannot escape the per-query budget                                       |
| UDP truncation (TC=1)         | Retry same query over TCP on port 53 via pooled TCP connection (see Phase 2)                                                                                            |
| IPv4 + IPv6 root hints        | Both address families stored; prefer IPv4 on single-stack hosts                                                                                                         |
| QNAME minimization (RFC 9156) | Each delegation hop queries only the next label, not the full QNAME                                                                                                     |
| EDNS0 OPT record              | Advertised on every outgoing query when `edns0_enabled = true`                                                                                                          |

#### Nameserver query concurrency (`query_any`)

Driven by `ns_concurrency`:

- **`"sequential"`**: try `ns_addrs[0]`; on timeout/error, move to `ns_addrs[1]`, etc. Lowest upstream load.
- **`"staggered"`**: launch `ns_addrs[0]`; if no response after `ns_stagger_ms`, launch `ns_addrs[1]` while `[0]` is still in flight, up to `max_concurrent_queries` additional launches. First valid response cancels the rest.
- **`"parallel"`**: launch up to `max_concurrent_queries` simultaneously. First valid response wins, rest cancelled. Antisocial to root/TLD operators if abused — keep `max_concurrent_queries` small.

For `staggered` and `parallel`, `queries_used` is incremented per _launched_ query (not per logical query) so amplification is correctly accounted for against `max_queries_per_resolution`.

---

### Root hints

Thirteen root server addresses (A + AAAA, 26 addresses total) are compiled in as a `const` array, sourced from IANA's published list as of the implementation date. `root_hints_path` overrides them when set at startup. Root hints do not reload at runtime (SIGHUP) — restart is required.

Random selection at each resolution spreads load across root operators.

**Drift protection**: see "Operational tasks" below — a CI job and a `just` recipe diff the compiled-in constants against IANA's published `named.root` weekly and fail CI on divergence.

---

## Popularity Cache & Decay

### `PopularityTracker`

A `DashMap<u64, PopularityEntry>` keyed by `xxh3_64(lowercase_domain)` using a **fixed seed of 0** — the seed must remain constant across runs because the persistence snapshot is keyed by this hash. Updated inside `handle_query` on every **allowed** cache hit (and from the prefetch worker on each successful prefetch). Blocked domains never enter the tracker by construction.

```rust
struct PopularityEntry {
    hit_count: u8,         // saturating_add(1) on each hit
    last_hit_at: Instant,  // process-local timestamp of the most recent hit
}
```

`DashMap` was chosen over alternatives (lock-free atomic array, single `RwLock<HashMap>`, separately-maintained top-N heap) for Phase 3 simplicity: it ships fast, matches existing project style, and is already a workspace dep. Revisit only if profiling on a real MIPS target shows snapshot iteration cost matters in practice.

### Decay formula — integer, no background task

Decay is computed lazily at **read time** using only integer arithmetic. No ticker, no background task.

```rust
fn effective_score(entry: &PopularityEntry, half_life_secs: u64) -> u8 {
    let elapsed = entry.last_hit_at.elapsed().as_secs();
    let periods = elapsed / half_life_secs;          // integer div: compiler emits multiply + shift
    if periods >= 8 { 0 } else { entry.hit_count >> periods }
}
```

`record_hit` resets `last_hit_at = Instant::now()` so fresh hits restart the decay clock against the (saturated) raw count.

Cost on MIPS (no FPU): one subtraction, one division-by-constant (compiler emits multiply + shift), one bit-shift. Effectively free per query.

With `decay_half_life_secs = 86400` (24 h): a domain not queried for 24 h retains half its score, for 48 h a quarter, for 192 h (8 days) zero. Daytime peaks are preserved across overnight gaps proportionally.

---

### Disk persistence

Written periodically and on clean shutdown. Loaded at startup if the file exists; ignored if absent or corrupt (fresh start).

**Crate**: `rkyv` (already a workspace dep, used by `host_index`). Zero-copy reads on load matter on MIPS. No new crate is added to the binary.

**Format**: `Vec<(u64, u8)>` — the top `save_top_domains` entries sorted descending by `effective_score`, where:

- `u64` = `xxh3_64(lowercase_domain, seed=0)`
- `u8` = `effective_score` **at the time of save**, not the raw `hit_count`

Persisting the **decayed** score (not the raw count) makes restart-time accuracy correct without serialising wall-clock timestamps. A snapshot written 24 h before a restart hands back already-halved scores; one written 10 min before hands back nearly-full scores. The decay clock then restarts from `Instant::now()` on load — acceptable because the snapshot already absorbed the elapsed wall time.

On startup the map is loaded into memory. When a client query arrives for a domain, its hash is looked up; if found, the persisted score is copied into the in-memory tracker's `hit_count` and `last_hit_at = Instant::now()`.

No domain name is stored. The hash is sufficient because the domain name is provided by the incoming query that triggers the lookup.

**Wear amortization**: writes are delta-based. Each save cycle, compute a quick fingerprint over the top-N list (e.g., `xxh3_64` over the concatenation of `(hash, score)` pairs in rank order); skip the write if unchanged since the last save. Idle home routers avoid pointless flash wear.

---

## Prefetch Worker

```
prefetch_worker(rx: Receiver<(String, u16)>, resolver: Arc<dyn UpstreamResolver>):
  interval = tokio::time::interval(interval_ms)

  while (domain, qtype) = rx.recv():
    interval.tick().await          // rate limit: at most one prefetch per interval_ms

    query = DnsPacket::new_query(domain, qtype)
    match resolver.resolve(&query).await:
      Ok(response):
        cache.insert(domain, qtype, response)
        popularity_tracker.record_hit(domain)
      Err(_): // silently drop; client will resolve on next TTL miss
```

**Trigger**: in `handle_query`, after serving from cache and updating `PopularityTracker`:

```rust
if expires_at.saturating_duration_since(Instant::now()).as_secs() < ttl_remaining_trigger_secs {
    let _ = prefetch_tx.try_send((dns_packet.domain.clone(), dns_packet.qtype)); // drops if full
}
```

**Filter bypass + blocklist correctness**: the prefetch worker calls `resolver.resolve()` directly, bypassing `resolve_with_score()`. By construction, only previously-allowed domains appear in the `PopularityTracker`.

To handle a blocklist update that newly blocks a previously-allowed domain: on blocklist reload (SIGHUP and runtime list refresh), **invalidate both the response cache and the `PopularityTracker`**. The next client query for any domain rebuilds them through the full filter pipeline. Cheap, fully correct, no per-prefetch filter cost.

**Metrics**:

- `prefetch_dropped_total` — `try_send` rejected because the channel was full
- `prefetch_completed_total` — successful prefetch + cache insert
- `prefetch_failed_total` — `resolver.resolve()` returned an error

---

## DNSSEC Interaction

In **forwarder mode**: the existing side-channel `hickory-resolver`-based DNSSEC validator (`dnssec.rs`) continues to work unchanged.

In **recursive mode** (until Phase 6 ships): DNSSEC validation must be integrated into the iterative delegation chain. The current side-channel approach is incompatible because root servers do not respond to recursive queries.

**Until Phase 6 is delivered, dgaard refuses to start when `mode = "recursive"` and `security.dnssec.enabled = true`**. The startup guard emits a clear error message naming both options:

```
ERROR: DNSSEC validation in recursive mode is not yet implemented (Phase 6).
       Either set [security.dnssec] enabled = false, or set [server] mode = "forwarder".
```

No silent downgrade of a security feature.

Once Phase 6 ships:

- `enabled = true` in recursive mode → iterative loop validates RRSIG at each delegation hop using `hickory-proto`'s DNSSEC primitives.
- `action = "block" | "log"` semantics preserved.
- `dnssec::init()` (side-channel) in `main.rs` is skipped when `mode = "recursive"`.
- The Phase 1 "refuse to start" guard is lifted.

---

## Operational tasks

### Root-hints drift check (CI + local)

The 13 compiled-in root server addresses drift over decades (e.g., B-root's 2017 address change). Detect drift before it bites a router image that nobody updates:

- **`justfile` recipe `check-root-hints`**:
  - Downloads `https://www.internic.net/domain/named.root`
  - Parses A + AAAA records for the 13 operators
  - Diffs against the compiled-in `const` array in `dgaard/src/dns/recursive.rs`
  - Exits `0` if match, `1` with a unified diff if not
- **`.woodpecker/` weekly job `root-hints`**:
  - Cron-triggered on master (e.g., Mondays 06:00 UTC)
  - Runs `nix develop --command just check-root-hints`
  - Fails the pipeline loudly on drift; maintainer regenerates the const array and opens a PR
- **CONTRIBUTING.md** documents the manual regeneration procedure for the const array.

### Resolver metrics (Phase 2)

Added to `STATS_COUNTERS`:

- `recursive_queries_total`
- `recursive_referrals_total`
- `recursive_glue_hit_total` / `recursive_glue_miss_total`
- `recursive_tcp_fallback_total`
- `recursive_cycle_detected_total`
- `recursive_depth_cap_hit_total`
- `recursive_query_cap_hit_total`
- `recursive_bailiwick_reject_total`

---

## Implementation Phases

### Phase 1 — Resolver abstraction & forwarder migration

- [x] Define `UpstreamResolver` trait in `dgaard/src/dns/resolver.rs` taking `&DnsPacket` (parsed, not raw bytes)
- [x] Wrap existing `forward_to_upstream` logic into `ForwardingResolver`
- [x] Add `OnceLock<Arc<dyn UpstreamResolver>>` global; initialise from config in `main.rs`
- [x] **Hard rename** `[upstream]` → `[forwarder]` in config model, parser, example file, and tests. Parser rejects `[upstream]` with a clear error message + CHANGELOG reference
- [x] Remove `if mode` branching from `handle_query`; it now calls `UPSTREAM_RESOLVER.get().resolve(&dns_packet)`
- [x] Refuse-to-start guard: if `mode = "recursive"` and `security.dnssec.enabled = true`, error out before binding sockets

### Phase 2 — Iterative recursive resolver

- [x] Implement `RecursiveResolver` in `dgaard/src/dns/recursive.rs`
- [x] Compile-in root hint constants (IPv4 + IPv6, all 13 operators)
- [x] Implement `root_hints_path` override at startup
- [x] Iterative delegation loop: referral extraction, **in-bailiwick glue check**, configurable bailiwick policy (`strict_bailiwick`)
- [x] Two threaded visited sets: `visited_zones: Vec<u64>` and `visited_cnames: Vec<u64>` — passed into CNAME-follow recursion and out-of-zone NS resolution so cycles spanning sub-resolves are detected
- [x] `queries_used: u32` global query counter capped by `max_queries_per_resolution` (default 64)
- [x] `max_delegation_depth = 8` hard fallback guard with SERVFAIL
- [x] **EDNS0 OPT record** on every outgoing query; advertise `edns0_udp_payload_size`
- [x] **ECS striping** in the OPT RR builder — never insert an EDNS0 Client Subnet (RFC 7871) option in outgoing recursive queries. Shared policy with forwarder mode, see Phase 10.7 in `Roadmap.md`. In recursive mode there is nothing to strip from an incoming client packet (the recursive resolver builds outgoing packets from scratch); the rule is simply _do not insert_ unless `[security.ecs] forward_as_prefix = true` is set, in which case insert a truncated `/24` (IPv4) or `/56` (IPv6) prefix derived from the client's address.
- [x] **QNAME minimization** (RFC 9156): query only the next label at each delegation hop
- [x] UDP truncation → **TCP fallback with pooled TCP connections** (mirror existing UDP `SocketPool` pattern from `dgaard/src/dns/upstream.rs`)
- [x] `ns_concurrency` policy: `sequential` | `staggered` | `parallel` with `max_concurrent_queries` and `ns_stagger_ms`; `queries_used` increments per launched query
- [x] Resolver metrics counters in `STATS_COUNTERS`
- [x] Integration tests:
  - `example.com`, NXDOMAIN, deep delegation, CNAME chain, delegation cycle, CNAME cycle across sub-resolves
  - Out-of-bailiwick referral (strict mode → SERVFAIL; lenient mode → next NS)
  - Bad / out-of-bailiwick glue discarded
  - TC=1 → TCP fallback path
  - EDNS0 echo / non-EDNS0 fallback
  - `max_queries_per_resolution` cap fires on amplifying chains

### Phase 3 — Popularity tracking & decay

- [x] Add `PopularityTracker` (`DashMap<u64, PopularityEntry>`) as a global; xxh3_64 with **fixed seed 0**
- [x] Update `handle_query` to call `tracker.record_hit(domain)` on allowed cache hits (and from prefetch worker)
- [x] Expose `effective_score()` with integer bit-shift decay, `decay_half_life_secs` from config
- [x] Unit tests: saturation at 255, decay across multiple half-lives, zero after 8 periods, `record_hit` resets the clock

### Phase 4 — Disk persistence

- [x] Background task: every `save_interval_secs`, compute top-`save_top_domains` by **effective score at save time**, serialize as `Vec<(u64, u8)>` via **rkyv**, write to `save_path`
- [x] Delta-based writes: skip if top-N fingerprint is unchanged since last save
- [x] Flush on clean shutdown (SIGTERM handler)
- [x] Startup: load file if present, populate in-memory tracker (copy `effective_score` into `hit_count`, set `last_hit_at = Instant::now()`); warn and continue if corrupt or version-mismatched
- [x] Blocklist reload also invalidates `PopularityTracker` and `ResponseCache`
- [x] Integration test: write → restart → verify decayed score restored on first query

### Phase 5 — Prefetch worker

- [ ] Bounded `mpsc::channel(queue_capacity)` for `(String, u16)` prefetch requests
- [ ] `start_prefetch_worker()` task: rate-limited by `interval_ms`, calls `resolver.resolve(&query)`
- [ ] Trigger in `handle_query`: `try_send` when remaining TTL < `ttl_remaining_trigger_secs`
- [ ] `prefetch_dropped_total`, `prefetch_completed_total`, `prefetch_failed_total` metrics
- [ ] Integration test: high-hit-count domain gets prefetched before TTL expires

### Phase 6 — DNSSEC in recursive mode (follow-on)

- [ ] Integrate `hickory-proto` DNSSEC primitives into the iterative loop
- [ ] Validate RRSIG at each delegation step
- [ ] Skip `dnssec::init()` (side-channel) when `mode = "recursive"`
- [ ] Lift the Phase 1 "refuse to start" guard once recursive DNSSEC is validated
- [ ] Preserve `action = "block" | "log"` semantics

### Operational (rolling) — root-hints drift check

- [ ] `justfile` recipe `check-root-hints` (download `named.root`, parse A+AAAA, diff against const array)
- [ ] `.woodpecker/` weekly cron job runs `nix develop --command just check-root-hints`; fails CI on drift
- [ ] CONTRIBUTING.md section documenting the manual constants-update procedure
