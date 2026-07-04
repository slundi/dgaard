# `digaard` — Ideas Beyond `dig`

This document tracks enrichment ideas that push `digaard` past a plain `dig`/`q` replacement into a **domain intelligence tool**. Each section explains the value added and why it is not a fit for traditional `dig`-style usage.

---

## Philosophy

`dig` is a wire-faithful tool: it shows exactly what the DNS protocol returned and nothing else. That is the right model for protocol debugging. `digaard` starts from the same base but adds an opt-in enrichment layer — contextual data pulled from complementary sources (GeoIP databases, RDAP registries, BGP tables) and printed inline or as structured JSON fields. Every enrichment is off by default and requires an explicit flag, so plain invocations remain fast and deterministic.

---

## Implemented

### GeoIP country annotations (`--geoip`)

**What it adds:** A/AAAA records are annotated with a 2-letter ISO country code (and optionally an emoji flag) derived from a local MaxMind-compatible `.mmdb` file.

```
example.com.  299  IN  A  93.184.216.34  [US]
```

**Why it differs from `dig`:** `dig` shows raw IPs. Geo context matters when checking CDN distribution, verifying anycast coverage, or spotting unexpected authoritative-server geography.

**Design choices:**

- Lookup is purely local (no outbound HTTP per query).
- Falls back gracefully if the database file is absent or the IP is unrouted.
- Controlled by `--geoip [<PATH>]`; path defaults to the XDG-configured mmdb location.

---

### Latency statistics (`--stats`)

**What it adds:** Per-query round-trip time, plus an end-of-run summary (min / avg / p50 / p95 / max / error rate) printed to stderr.

**Why it differs from `dig`:** `dig` shows one `Query time:` line for one query. For batch workloads (`-f domains.txt -j 32`) a single number is meaningless — the percentile distribution tells you about tail latency and resolver consistency.

---

## Planned

### RDAP registration data (`--rdap`)

**What it adds:** After resolving a domain, fetch its RDAP record from the authoritative registrar endpoint and display key registration fields inline:

| Field         | Example value                     |
| ------------- | --------------------------------- |
| Registrar     | `MarkMonitor Inc.`                |
| Registered    | `1995-08-14`                      |
| Expires       | `2025-08-13`                      |
| Last updated  | `2024-08-09`                      |
| Status        | `clientTransferProhibited`        |
| Abuse contact | `abusecomplaints@markmonitor.com` |
| Name servers  | `NS1.EXAMPLE.COM` …               |

**Why RDAP and not WHOIS:**

| Dimension        | WHOIS (port 43)               | RDAP (HTTPS, RFC 7480+)                       |
| ---------------- | ----------------------------- | --------------------------------------------- |
| Format           | Free-text, registrar-specific | Structured JSON, standardized                 |
| Parsing          | Fragile regex per registrar   | `serde_json` deserialization                  |
| Server discovery | Manual `whois -h` lookup      | IANA bootstrap JSON (`rdap.iana.org`)         |
| GDPR redaction   | Inconsistent, often garbled   | Structured `redacted` objects in the response |
| Rate limiting    | Common, poorly signaled       | HTTP 429 with `Retry-After`                   |
| TLS              | No                            | Yes (standard HTTPS)                          |

**Why it differs from `dig`:** `dig` only speaks DNS. Registration data lives in a completely separate protocol (RDAP) served by registrars, not name servers. `digaard --rdap` correlates both layers in a single command — useful for incident response, phishing triage, and domain expiry checks.

**Implementation notes:**

- Server discovery: fetch `https://data.iana.org/rdap/dns.json` once, cache per TLD, derive the correct RDAP base URL.
- HTTP client: `reqwest` (already pulled in via workspace, tokio-compatible).
- Output: additional `[RDAP]` section in pretty mode; extra top-level fields in JSON mode.
- No RDAP data is fetched unless `--rdap` is explicitly passed (avoids surprise outbound traffic in batch mode).
- Rate-limit awareness: respect `Retry-After`; back off and warn rather than hard-fail.

**Flag sketch:**

```
--rdap              Fetch and display RDAP registration data for each queried domain
--rdap-fields <F>   Comma-separated subset of fields to show (default: registrar,dates,status,abuse)
```

---

### ASN / BGP prefix annotation (`--asn`)

**What it adds:** Annotate A/AAAA records with the originating AS number, AS name, and announced prefix.

```
example.com.  299  IN  A  93.184.216.34  [US | AS15133 EDGECAST | 93.184.216.0/24]
```

**Why it differs from `dig`:** Useful for understanding hosting infrastructure, detecting BGP hijacks, or correlating IPs across bulk lookups. Complements GeoIP — an IP can be in a US data center but announced by a non-US AS.

**Implementation options:**

- Local `routeviews` / `RIPE` prefix database (large, requires periodic updates).
- Team Cymru IP-to-ASN DNS service (`origin.asn.cymru.com`) — lightweight, no local database, works as a secondary DNS query.
- Default to Cymru DNS approach (zero local storage); offer `--asn-db <PATH>` for offline environments.

---

### Reverse PTR auto-annotation

**What it adds:** When printing A/AAAA records, optionally auto-resolve each IP to its PTR name and show it inline — without requiring a separate `-x` invocation.

```
example.com.  299  IN  A  93.184.216.34  → 93.184.216.34.in-addr.arpa → 93-184-216-34.any.example.com.
```

**Why it differs from `dig`:** `dig` requires a separate `dig -x <ip>` call. `digaard --ptr` does it concurrently as part of the same batch, using the existing fan-out infrastructure.

---

### TLS certificate info for HTTPS records (`--cert`)

**What it adds:** For domains with `HTTPS` SVCB records (or when a DoH/DoT server is resolved), optionally connect and display the leaf certificate's SANs, expiry, and issuer.

**Why it differs from `dig`:** Certificate validation is entirely outside DNS, but `HTTPS` records exist precisely to advertise HTTPS service parameters. Showing cert expiry alongside the record catches mismatches before users do.

---

## Non-ideas (explicitly ruled out)

- **Caching / resolver logic** — `digaard` is a pure client; it sends one query and prints one response. No CNAME chasing, no negative caching.
- **Zone transfer (AXFR)** — not in scope for enrichment; belongs to a separate diagnostic subcommand if ever added.
- **Raw WHOIS (port 43)** — superseded by RDAP; adding a fragile text-scraping layer would require per-registrar maintenance burden with no benefit over RDAP.
