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

The genuinely new work is the IP and email indicator logic, a persistent pipelined wire
protocol, and an EVE JSON ingestion path. Everything else is already paid for.

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
service. Remote lookups belong in an out-of-band enrichment path with a persistent cache,
or are left out entirely for v1.

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

## 4. Open questions to resolve before writing code

1. **What is the target latency budget, and at what event rate?** This single answer decides
   out-of-band vs inline, and therefore most of the architecture.
2. **Who is the consumer — Suricata itself (rules, inline) or the NDR downstream (events)?**
   The two want different APIs. Trying to serve both with one shape produces a bad fit for
   each.
3. **Are remote reputation APIs a real requirement or a nice-to-have?** If real, they impose
   an asynchronous architecture and a persistent cache on everything else. If not, v1 stays
   entirely local and is dramatically simpler.
4. **Is email in scope for an NDR product at all**, or does it belong with the MTA sidecar?

---

## 5. Suggested shape for v1

```
dgaard-enrich/          new — multi-indicator engine, no I/O
  domain.rs             delegates to dgaard-engine
  hostname.rs           domain + internal-name detection
  ip.rs                 MaxMind mmap, ASN, local reputation sets
  email.rs              split on '@', domain half only
  verdict.rs            versioned, stable output schema

dgaard-daemon/          extended — pipelined binary protocol, UDS + TCP
dgaard-rest/            extended — /api/v1/enrich endpoint
dgaard-eve/             new, thin — EVE JSON reader → enrich → annotated output
```

Smallest useful first deliverable: `dgaard-eve` in out-of-band mode, local datasets only,
domain + hostname + GeoIP/ASN. It has no latency constraint, cannot destabilise a sensor,
and produces evidence on cache hit rates and which indicators actually carry signal — which
is exactly what is needed to decide whether the inline path is worth building.
