# Enrichment Service for Suricata / NDR — Feasibility Report

**Status:** design note, no code written
**Date:** 2026-10-04
**Question asked:** should we build a separate tool that enriches domains, emails, IPs and
hostnames for Suricata and NDR consumers — and should it listen on a Unix socket or a
network port?

---

## 1. Verdict

The use case is real and worth building. The _packaging_ proposed is not: this should not be
a new standalone tool.

The workspace already contains roughly 70 % of the plumbing. A thirteenth crate that
re-implements a server loop, a config discovery chain, a cache and a graceful-shutdown path
is duplication, not a product. The decomposition that holds is:

- a new **`dgaard-enrich`** engine crate — multi-indicator scoring (domain, IP, email,
  hostname), no I/O, no transport;
- consumed by the **existing** frontends, extended rather than cloned.

### What already exists

| Capability                     | Where                                                            |
| ------------------------------ | ---------------------------------------------------------------- |
| Domain / NRD scoring           | `dgaard-engine/`                                                 |
| Unix socket frontend           | `dgaard-daemon/`                                                 |
| HTTP/JSON frontend             | `dgaard-rest/`                                                   |
| GeoIP / MaxMindDB              | `digaard/src/geoip.rs`, `geoip` cargo feature (commit `58a0cc6`) |
| Atomic config/blocklist reload | `arc-swap` + `SIGHUP`, in both frontends                         |
| Event transport                | `dgaard-monitor-nats/`                                           |

The genuinely new work is the IP and email indicator logic, the asynchronous remote-source
track and its admission control (§4 — the hard part), a persistent pipelined wire protocol,
and an EVE JSON ingestion path. Everything else is already paid for.

---

## 2. Per-indicator assessment

### 2.1 Domain — strong

This is the existing core competency. Nothing to re-litigate.

### 2.2 Hostname — strong, small delta

A hostname is a domain plus internal-name detection: RFC1918 reverse names, `.local` /
mDNS, NetBIOS and workgroup names, Kerberos realms. The reverse-DNS exemption added to
`max_subdomain_depth` (commit `c000e58`) is the first piece of this.

Real NDR sources for hostnames: TLS SNI, HTTP `Host:`, DHCP hostname option, Kerberos
`CNameString`, SMB session setup. These must **not** be scored with the same thresholds as
public domains — internal naming conventions routinely look high-entropy
(`WKS-A7F3K2.corp.local`).

### 2.3 IP — strong, but must be split in two

Two source families with incompatible latency profiles:

| Family             | Examples                                                                                    | Latency                         | Hot path? |
| ------------------ | ------------------------------------------------------------------------------------------- | ------------------------------- | --------- |
| **Local datasets** | MaxMind City/ASN (mmap), Spamhaus DROP, Tor exit list, bogon ranges, local reputation files | µs                              | Yes       |
| **Remote APIs**    | AbuseIPDB, VirusTotal, GreyNoise, Shodan                                                    | 100 ms–several s, quota-limited | **No**    |

Putting both behind one synchronous API is the classic failure mode of this kind of
service. The answer is not to drop remote sources but to run them on a second, asynchronous
track — see §4, which is the core of the design.

Note also that Suricata has a built-in `geoip` keyword (backed by libmaxminddb). If GeoIP is
all that is needed inline, the service adds nothing there — its value is the correlation of
GeoIP with ASN, reputation and the domain verdict.

### 2.4 Email — weakest of the four; scope it carefully

The domain half is free: split on `@`, feed the right-hand side to the existing engine.

The entropy heuristic on the local part is the problem. Legitimate addresses that look
random are extremely common:

- VERP / bounce addresses — `bounces+12345-a1b2c3@`, `srs0=abc1=xy=domain=user@`
- Apple Private Relay, Firefox Relay, and similar alias services
- hashed or tokenised addresses from marketing platforms
- auto-generated service accounts and ticketing addresses

Local-part entropy is only usable with context — direction, volume, reputation of the
domain, whether the address was ever seen before. On its own it will generate noise.

There is also a scoping question. Emails reach an NDR only through EVE `smtp` events
(`MAIL FROM`, `RCPT TO`) or parsed message headers. That is a narrow slice of NDR traffic,
and the MTA use case is already served by `dgaard-daemon`. Email enrichment may belong to
the spam-filter product line rather than this one.

**Recommendation:** ship domain-half email enrichment in v1; defer local-part heuristics
until there is a corpus to validate them against.

---

## 3. Transport: Unix socket vs network port

This is the wrong axis to optimise on.

For small messages, a Unix domain socket beats loopback TCP by roughly 1.5–2×, on round
trips already in the tens of microseconds. Both transports are already present in the
workspace (`dgaard-daemon` uses `UnixListener`, `dgaard-rest` uses `TcpListener`), and under
tokio they are the same accept loop modulo about twenty lines.

**Decision: do not choose. Abstract the listener and support both.**

- Unix socket as the default — filesystem permissions give access control for free, and the
  existing `0o600` behaviour is the right posture.
- TCP for containerised or remote deployments, where the socket cannot be shared.

The transport choice is not where the throughput comes from. The following four are, in
descending order of impact.

### 3.1 Integration mode (largest single factor)

| Mode                                    | Mechanism                                                                                     | Latency constraint | Risk                                                     |
| --------------------------------------- | --------------------------------------------------------------------------------------------- | ------------------ | -------------------------------------------------------- |
| **Out-of-band** _(recommended default)_ | Consume EVE JSON (file tail, Unix socket, Redis, Kafka) and enrich events after the fact      | None               | None to the sensor                                       |
| **Suricata-native datasets**            | Produce `dataset` / `datarep` files (and `datajson` on Suricata 8) consumed directly by rules | None at match time | Only works for pre-computable verdicts                   |
| **Inline via Lua**                      | Lua script in a rule calls the service over IPC                                               | Very tight         | IPC runs on the detection thread — a stall drops packets |

The out-of-band mode removes the latency constraint entirely and cannot destabilise the
sensor. It is also what most NDR stacks already do. Start there.

The dataset mode is worth serious consideration for domains: for anything pre-computable,
becoming a _producer of Suricata datasets_ beats being a service that Suricata queries —
there is no IPC at all.

Inline Lua should be treated as an advanced, opt-in mode with a hard latency budget.

### 3.2 Wire protocol (second largest factor)

The current `dgaard-daemon` protocol — _one domain per connection, reconnect for each
query_ — is precisely the worst case for this workload. Connection setup dominates the
actual lookup by an order of magnitude at NDR event rates.

What is needed:

- persistent connections;
- length-prefixed framing;
- pipelining with request IDs, so responses may return out of order;
- batch requests (N indicators per frame);
- a compact binary codec — `postcard` is already a preferred dependency — rather than
  JSON-per-query. Keep a JSON mode for debuggability and for `dgaard-rest`.

### 3.3 Cache

This is where the performance actually comes from. Network traffic repeats the same
domains, SNI values and IPs massively; a bounded LRU in front of the engine absorbs the
large majority of queries. Both `lru` and `arc-swap` are already workspace dependencies.

Measure the hit rate before optimising anything in the transport layer.

### 3.4 Fail-open semantics

Specify this at design time, not after the first incident: on timeout, queue saturation, or
engine reload, the service returns an `unknown` verdict and never blocks the caller. In
inline mode a blocking enrichment service is a packet-loss generator.

---

## 4. The two-speed model — instant _and_ asynchronous

Remote sources are a real requirement, not a nice-to-have. They must not be dropped, and
they must not be allowed to block. The resolution is a service with two tracks sharing one
cache.

### 4.1 Contract

Every query is answered **immediately** from local data. If the indicator would benefit from
a remote source that is not cached, the service additionally schedules a background fetch
and says so in the response.

```
request  → { id: 42, indicator: { ip: "203.0.113.7" }, mode: "trigger_async" }
response → { id: 42, rev: 1, complete: false,
             verdict: { score: 3, ... },
             sources: { geoip: "ok", asn: "ok", abuseipdb: "pending" } }

... 800 ms later, on the push channel ...

update   → { id: 42, rev: 2, complete: true,
             verdict: { score: 8, ... },
             sources: { geoip: "ok", asn: "ok", abuseipdb: "ok" } }
```

The response-time guarantee is therefore a property of the local track alone, and remains
in microseconds regardless of how slow or broken the remote providers are.

### 4.2 Revisable verdicts

This is the part that must be designed in from the start, because it propagates to every
consumer: **a verdict is a revision, not a final answer.** Each carries `rev`, `complete`,
and a per-source status map. Consumers that cannot handle a late-arriving update simply
ignore revisions after the first — they degrade to local-only, which is exactly the inline
Suricata case.

Every field in the verdict carries provenance: which source produced it, when it was
fetched, and how stale it is. Without that, nothing downstream can tell a three-second-old
AbuseIPDB score from a three-week-old one.

### 4.3 Query modes

The client declares what it wants; one service serves all three.

| Mode            | Behaviour                                                                      | Caller                                     |
| --------------- | ------------------------------------------------------------------------------ | ------------------------------------------ |
| `local_only`    | Local data, never schedules a fetch, never waits                               | Inline Lua, hot path                       |
| `trigger_async` | Local data now, schedules remote fetch, result arrives as a revision           | NDR event enrichment (the default)         |
| `wait(ms)`      | Local data, then blocks up to `ms` for remote sources, returns whatever landed | Analyst tooling, retro-hunts, batch replay |

`wait` is a bounded convenience, not a different code path — it is `trigger_async` plus a
timeout on the revision channel. The timeout is a hard ceiling, and expiry returns the
partial verdict rather than an error.

### 4.4 Delivering the async result

Three delivery mechanisms, in order of how much they are worth:

1. **Cache fill (always on).** Even with no delivery channel at all, the background fetch
   populates the cache so the _next_ query for that indicator is instant. Given how heavily
   network traffic repeats indicators, this alone captures most of the value, and it is the
   only mechanism with zero protocol surface.
2. **Push over NATS.** `dgaard-monitor-nats/` already exists. The NDR is re-indexing events
   anyway; publishing verdict revisions to a subject it subscribes to fits that model
   naturally and decouples the service from consumer availability.
3. **Server-initiated frames on the query socket**, correlated by request ID. Useful for a
   client that holds a persistent connection and wants revisions without a message bus.
   Requires the protocol of §3.2 to be bidirectional — worth noting now even if implemented
   later.

A poll endpoint (re-query the indicator, get whatever is cached) is the fallback for simple
clients and costs nothing, since it is just a `local_only` query after the cache filled.

### 4.5 Admission control — where this design actually fails

The asynchronous track is easy to build and easy to get badly wrong. Remote providers have
hard quotas (AbuseIPDB's free tier is on the order of a thousand checks per day; a
mid-sized sensor sees that many distinct external IPs in minutes). Without the following,
the queue becomes an unbounded memory leak that exhausts the daily quota in the first ten
minutes and then returns nothing useful for the rest of the day.

- **Pre-filter before enqueueing.** Never spend a quota slot on RFC1918, CGNAT, bogons,
  known CDN/cloud ranges, the organisation's own ASNs, or anything already locally
  classified. This is the single highest-leverage control, and it is cheap — it reuses the
  local track's data.
- **Single-flight / dedup.** N concurrent queries for the same indicator collapse to one
  outbound request. At NDR event rates the same IP arrives hundreds of times per second.
- **Bounded queue with explicit drop policy.** Fixed capacity, a counter for what was
  dropped, and an ordering discipline — which is involved enough to have its own section
  (§5.4–5.5). Silent unbounded growth is not an option.
- **Per-provider token bucket**, configured from the documented quota rather than discovered
  by being rate-limited. Honour `Retry-After`.
- **Circuit breaker.** A provider that is down or over quota gets marked `unavailable` in
  the source map and stops being called, rather than contributing timeouts to every query.
- **Negative caching with per-source TTL.** "AbuseIPDB has nothing on this IP" is a result
  worth storing. Without it, clean IPs are re-queried forever.

### 4.6 Persistent cache

The async cache must survive restart, or every daemon restart re-burns the daily quota.
`redb` or `rusqlite` (both already preferred dependencies) with per-source TTL and an
explicit size cap. The local track keeps its in-memory LRU in front of it.

This also makes the cache useful independently: a persistent store of "what we know about
this indicator, when we learned it, and from whom" is itself a product surface — queryable
by analysts, exportable to Suricata datasets.

---

## 5. Scheduling and priority

"Fast queries first, slow ones after, configurable" is right, but it decomposes into four
distinct mechanisms operating at different layers. Conflating them produces a scheduler
nobody can reason about.

### 5.1 Isolation before priority

The local track must never be delayed by the async track. The robust way to guarantee that
is not priority scheduling but **construction**: the local track performs no I/O that can
block — mmap lookups, in-memory structures, nothing awaiting a socket. The async track runs
on its own worker pool with a hard concurrency cap and its own queue.

Two pools that cannot contend beat one pool with priorities, because priority inversion and
queue-head blocking are failure modes that only appear under load — i.e. exactly when the
service matters. Get the isolation right and most of the scheduling problem disappears.

### 5.2 Per-request: cost-ordered enrichers with short-circuit

Within the local track, order enrichers by cost and allow early exit. If an indicator is
already hard-blocked by a blocklist hit, there is no reason to compute entropy, run the
GeoIP lookup, or walk the ASN table.

```
blocklist / whitelist hit   ~100 ns   → may short-circuit
bogon / RFC1918 / own-ASN   ~100 ns   → may short-circuit
structural checks (length, depth, TLD)
entropy / heuristics        ~µs
GeoIP + ASN mmap            ~µs       → page fault possible on cold cache
```

Each enricher declares a cost class and whether it is conclusive. The chain is data, not
hard-coded control flow, which is also what makes §5.6 possible.

### 5.3 Incremental revisions — "fast first" for free

Do not batch the async result. Emit a revision **as each source resolves**, rather than one
revision once all of them have. A fast provider lands in `rev: 2` at 80 ms; a slow one in
`rev: 3` at 2 s; a dead one never arrives and stays `pending` until the circuit breaker
marks it `unavailable`.

This makes "fast queries first" emergent rather than scheduled, and it removes the need for
any shortest-job-first discipline across providers. It costs one thing: consumers must
tolerate more than two revisions per indicator. Given §4.2 already requires them to tolerate
revisions at all, this is nearly free — but it must be stated in the contract, not
discovered.

### 5.4 Async queue priority: the scarce resource is quota, not CPU

This is the only place where genuine priority scheduling is needed. The constraint is not
throughput — it is that a provider allows N calls per day and the sensor sees far more
distinct indicators than that. Priority decides **which indicators are worth a quota slot**.

Useful signals, roughly in order of value:

| Signal                         | Rationale                                                                                                                                                  |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **An alert fired on the flow** | By far the strongest. If Suricata already alerted, that peer is worth a quota slot; a random background connection is not. Natural fit with EVE ingestion. |
| Local suspicion score          | The local track's own output feeds the priority — cheap, already computed                                                                                  |
| Novelty (first-seen)           | A never-before-seen external peer carries more information than the 500th repeat                                                                           |
| Asset criticality              | Requires a user-supplied asset/subnet list; high value where it exists                                                                                     |
| Direction and role             | Inbound to an exposed service ≠ outbound to a CDN                                                                                                          |
| Cache staleness                | Refreshing a 29-day-old entry ranks below filling a cold one                                                                                               |

Note the dependency: three of these come from the local track, which is why §6 builds it
first.

### 5.5 Starvation and deadlines

Any priority queue needs both of the following, or it fails in predictable ways.

**Anti-starvation.** Under strict priority, low-priority classes are never served — the
queue simply grows until the drop policy evicts them, and the operator sees "enrichment
doesn't work for normal traffic". Use **weighted fair queueing with reserved shares** per
class rather than strict ordering: e.g. alert-bearing 60 %, novel 30 %, refresh 10 % of the
quota. A high-priority flood then cannot consume the whole budget. Aging is the simpler
alternative but tunes badly.

**Deadlines.** A queued item should carry an expiry and be dropped when it passes, not
retried forever. An enrichment landing forty minutes after the event is useless if the NDR
has already indexed and closed it — and worse, it spends a quota slot that a live event
needed. Deadlines bound the damage of a backlog in a way that priority alone does not.

Both need counters: dropped-by-deadline, dropped-by-capacity, and per-class service rate.
Without them a misconfigured weighting is invisible.

### 5.6 What to make configurable — and what not to

The pressure here is to expose a policy language. Resist it: a user-writable scheduling
expression is hard to debug, trivially creates starvation, and makes every support question
unanswerable.

Expose instead:

- **enricher chain** — order, enable/disable, and the short-circuit flag per enricher;
- **priority weights** — a fixed set of named signals (§5.4) with numeric weights, so the
  scoring function is fixed and only its coefficients vary;
- **class shares** — the reserved percentages of §5.5;
- **per-provider budget** — calls per day/minute, concurrency, timeout, deadline;
- **pre-filter sets** — own ASNs, trusted CDN ranges, asset list, never-enrich ranges. This
  is the control with the most leverage and the one operators most need to own.

Do not expose: arbitrary ordering predicates, per-indicator scripting hooks, or unbounded
queue sizes. Ship a default profile that works with no configuration at all, and make every
knob optional.

```toml
[enrich.priority]
weights = { alert = 100, suspicion = 20, novelty = 10, asset = 30, staleness = -5 }
shares = { alert = 0.6, novel = 0.3, refresh = 0.1 }
deadline_ms = 30_000

[enrich.provider.abuseipdb]
calls_per_day = 1000
concurrency = 2
timeout_ms = 3000
```

---

## 6. Open questions to resolve before writing code

1. **What is the target latency budget on the local track, and at what event rate?** This
   decides how aggressive §3.2 and §3.3 need to be. The async track is unaffected.
2. **Who is the consumer — Suricata itself (rules, inline) or the NDR downstream (events)?**
   Inline wants `local_only` and never sees a revision; the NDR wants `trigger_async` and
   must be able to update an already-indexed event. If the NDR cannot re-index, revisions
   are worthless to it and the async track degrades to cache-fill only — worth confirming
   before building the push channel.
3. **Which remote providers, with which quotas and licence terms?** The quota numbers are
   direct inputs to §4.5; some providers also forbid caching or redistribution, which
   constrains §4.6.
4. **Can the pipeline correlate an indicator back to whether an alert fired on its flow?**
   This is the strongest priority signal (§5.4) and it is only available if enrichment sits
   downstream of detection, or can join on `flow_id`. If it cannot, priority loses most of
   its value and the queue is effectively novelty-ordered.
5. **Is email in scope for an NDR product at all**, or does it belong with the MTA sidecar?

---

## 7. Suggested shape for v1

```
dgaard-enrich/          new — multi-indicator engine
  local/                synchronous track, no I/O beyond mmap
    domain.rs           delegates to dgaard-engine
    hostname.rs         domain + internal-name detection
    ip.rs               MaxMind mmap, ASN, local reputation sets
    email.rs            split on '@', domain half only
  chain.rs              cost-ordered enricher chain with short-circuit (§5.2)
  remote/               asynchronous track, own worker pool (§5.1)
    provider.rs         trait: one impl per API, declares its quota
    scheduler.rs        pre-filter, single-flight, token bucket
    queue.rs            weighted fair queue, priority scoring, deadlines (§5.4–5.5)
    breaker.rs          per-provider circuit breaker
  cache.rs              in-memory LRU over a redb/rusqlite store, per-source TTL
  verdict.rs            revisable, versioned schema with per-source provenance

dgaard-daemon/          extended — pipelined bidirectional protocol, UDS + TCP
dgaard-rest/            extended — /api/v1/enrich, with ?mode= and an SSE revision stream
dgaard-eve/             new, thin — EVE JSON reader → enrich → annotated output
```

### Build order

The two tracks are separable, and the local one is a prerequisite for the other — its
classification data is what the async pre-filter (§4.5) uses to decide whether an indicator
deserves a quota slot. Building remote-first means building the scheduler blind.

1. **`dgaard-enrich` local track + revisable verdict schema.** The `rev` / `complete` /
   per-source-status shape must exist from the first commit even while every source is local
   and every answer is `complete: true` — retrofitting it later breaks every consumer.
   Build the enricher chain as data (§5.2) from the start; retrofitting ordering into
   hard-coded control flow is the expensive version.
2. **`dgaard-eve` out-of-band, local only.** No latency constraint, cannot destabilise a
   sensor. Produces the evidence needed for everything after: cache hit rates, indicator
   cardinality per hour, how many indicators per hour are alert-bearing — which is what
   tells you whether the quota is even a binding constraint — and which indicators actually
   carry signal.
3. **Persistent cache + one remote provider** behind the full §4.5 admission control, with
   a simple FIFO queue and deadlines but **no** priority scoring yet. One provider, not
   three — the scheduler is the hard part and is best debugged against a single quota.
   Cache-fill delivery only at this stage.
4. **Priority scheduling** (§5.4–5.5), once step 3's counters show the queue is actually
   saturating. If the pre-filter turns out to keep demand under quota, priority is dead
   code — build it when the drop counters say it is needed, not before.
5. **Push channel** (NATS), once step 2 has shown what the real revision rate is.
6. **Inline path** (pipelined protocol, `local_only` mode, Lua glue) — last, and only if the
   measured event rate justifies it over the dataset-producer approach of §3.1.

Steps 1–2 are the smallest useful deliverable and stand on their own. Step 3 is where the
design risk concentrates. Step 4 is deliberately deferred: the §5 design should be settled
on paper now, because it constrains the queue's data model, but writing a weighted fair
queue before knowing the real arrival rate is premature.
