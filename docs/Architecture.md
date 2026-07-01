# Architecture

## 1. System Architecture Overview

Relationship between all workspace crates. Solid arrows = Rust compile-time dependency. Dashed arrow = runtime communication.

```mermaid
flowchart TD
    subgraph utils["Utility CLIs"]
        ABP["adblockptimize<br/>list optimizer"]
        LS["list-stats<br/>analytics"]
    end

    subgraph core["Filtering Core"]
        ENGINE["dgaard-engine<br/>(library — no async/network)"]
    end

    subgraph ifaces["Runtime Interfaces"]
        DGAARD["dgaard<br/>DNS proxy · :5353"]
        DAEMON["dgaard-daemon<br/>Unix socket daemon"]
        REST["dgaard-rest<br/>HTTP API · :8080"]
        MONITOR["dgaard-monitor<br/>TUI dashboard"]
    end

    DGAARD --> ENGINE
    DAEMON --> ENGINE
    REST   --> ENGINE
    DGAARD -.->|"Postcard telemetry<br/>Unix socket"| MONITOR
```

---

## 2. Stratified Filtering Pipeline

Every DNS query passes through up to 9 stages inside `dgaard-engine`. Stage 0 is checked first and, when matched, bypasses all subsequent stages entirely. Stages 1–8 can each short-circuit to **Block** or **Allow**; otherwise the query falls through to the next stage.

```mermaid
flowchart TD
    IN([DNS Query]) --> S0

    S0["0. Domain Override<br/>[overrides] table — exact or *.wildcard match"]
    S1["1. Fast-Drop Gatekeeper<br/>ASCII + structural validation"]
    S2["2. Zero-Copy Whitelist<br/>xxh64 hash lookup"]
    S3["3. Smart-IDN Blocker<br/>Punycode + homograph check"]
    S4["4. Tiered Blacklist<br/>Bloom filter + rkyv FSTs"]
    S5["5. Heuristic Engine<br/>Entropy · N-Gram · Lexical"]
    S6["6. Behavioral Analytics<br/>NXDOMAIN hunting + tunneling"]
    S7["7. GeoIP Scoring<br/>MaxMind MMDB lookup"]
    S8["8. Custom TI Flags<br/>16 user-defined bitflags"]

    OVERRIDE(["Override — return fixed IP<br/>(Action::Override — skips all filters)"])
    BLOCK(["Block — return NXDOMAIN"])
    ALLOW(["Allow — proxy to upstream"])

    S0 -->|matched| OVERRIDE
    S0 -->|no match| S1
    S1 -->|invalid| BLOCK
    S1 -->|valid| S2
    S2 -->|whitelisted| ALLOW
    S2 -->|miss| S3
    S3 -->|IDN attack| BLOCK
    S3 -->|safe| S4
    S4 -->|matched| BLOCK
    S4 -->|miss| S5
    S5 -->|DGA detected| BLOCK
    S5 -->|clean| S6
    S6 -->|suspicious| BLOCK
    S6 -->|clean| S7
    S7 -->|score too high| BLOCK
    S7 -->|pass| S8
    S8 -->|flagged| BLOCK
    S8 -->|pass| ALLOW
```

---

## 3. Network Deployment Context

How dgaard sits in a typical LAN (home router, OpenWrt, or SME edge).

Clients can reach dgaard either directly (when dgaard owns `:53`) or via dnsmasq (common on OpenWrt where dnsmasq already handles DHCP and DNS on `:53`, and forwards to dgaard on `:5353`).

```mermaid
flowchart LR
    subgraph lan["LAN"]
        C1["Client"]
        C2["Client"]
        C3["Client"]
        GW["dnsmasq<br/>OpenWrt / router<br/>forwards to :5353"]
    end

    subgraph host["Dgaard Host — OpenWrt / Linux"]
        DG["dgaard<br/>:53 or :5353 UDP/TCP"]
        CACHE["LRU Response Cache<br/>(TTL-aware)"]
        MON["dgaard-monitor<br/>TUI dashboard"]
        DG <--> CACHE
        DG -->|"Unix socket<br/>telemetry"| MON
    end

    subgraph up["Upstream DNS"]
        DOT["DNS-over-TLS<br/>1.1.1.1 · 8.8.8.8<br/><i>forwarder mode</i>"]
        ROOT["IANA Root Servers<br/>a–m.root-servers.net<br/><i>recursive mode — iterative walk</i>"]
    end

    C1 -->|":53 direct"| DG
    C2 -->|":53 direct"| DG
    C3 -->|":53 via dnsmasq"| GW
    GW  -->|":5353"| DG
    DG  -->|"[server] mode = forwarder"| DOT
    DG  -->|"[server] mode = recursive"| ROOT
```

---

## 4. Inter-Component Communication

Protocols and data formats used between components at runtime.

```mermaid
flowchart LR
    ENGINE["dgaard-engine<br/>(shared library)"]

    DGAARD["dgaard<br/>DNS proxy"]
    DAEMON["dgaard-daemon"]
    REST["dgaard-rest"]
    MON["dgaard-monitor<br/>TUI"]
    APPS["Custom app<br/>(embedded lib)"]

    MTA["MTA / spam filter"]
    SIEM["SIEM / HTTP client"]

    DGAARD -->|"Rust crate dep"| ENGINE
    DAEMON -->|"Rust crate dep"| ENGINE
    REST    -->|"Rust crate dep"| ENGINE
    APPS    -->|"Rust crate dep"| ENGINE

    DGAARD -->|"Postcard binary<br/>Unix socket"| MON

    MTA    -->|"domain string<br/>newline · Unix socket"| DAEMON
    DAEMON -->|"JSON score<br/>newline-terminated"| MTA

    SIEM -->|"POST /api/v1/check<br/>HTTP JSON"| REST
    REST -->|"JSON score<br/>HTTP response"| SIEM
```

---

## 5. Blocklist Data Pipeline

How raw adblock lists are processed into the in-memory structures that `dgaard-engine` queries at runtime.

```mermaid
flowchart LR
    subgraph input["Input Sources"]
        AL["Adblock lists<br/>(EasyList, uBlock…)"]
        TI["Custom TI feeds"]
        MMDB["MaxMind MMDB<br/>(GeoIP)"]
        NGM["N-Gram models<br/>(language probability)"]
    end

    subgraph proc["Processing"]
        ABP["adblockptimize<br/>deduplicates + splits rules"]
    end

    subgraph artifacts["Optimized Artifacts"]
        DNS["DNS blocklists<br/>(network-level rules)"]
        CSS["Browser rules<br/>(cosmetic CSS/JS)"]
    end

    subgraph mem["Engine In-Memory Structures"]
        BLOOM["Bloom filter<br/>(low-RAM probabilistic)"]
        FST["rkyv FSTs<br/>(zero-copy suffix match)"]
        EXACT["Exact hash map<br/>(xxh64)"]
    end

    FE["FilterEngine<br/>(dgaard-engine)"]

    AL   --> ABP
    ABP  --> DNS
    ABP  --> CSS
    DNS  --> BLOOM
    DNS  --> FST
    DNS  --> EXACT
    TI   --> FE
    MMDB --> FE
    NGM  --> FE
    BLOOM --> FE
    FST   --> FE
    EXACT --> FE
```

> Hot-reload: on `SIGHUP`, `FilterEngine` is rebuilt from disk and swapped atomically via `arc-swap` — zero query loss.

---

## 6. Iterative Recursive Resolver

When `[server] mode = "recursive"`, dgaard resolves queries itself by walking the DNS delegation hierarchy from the IANA root servers down to the authoritative nameserver — no external forwarder involved.

```mermaid
flowchart TD
    IN([Client Query]) --> ROOTS

    ROOTS["Seed NS pool\n3 random addresses from 26 compiled-in\nIANA root hints — IPv4 + IPv6"]
    ROOTS --> CAPS

    CAPS{"Query or depth\ncap exceeded?"}
    CAPS -->|Yes| FAIL(["SERVFAIL"])
    CAPS -->|No| QUERY

    QUERY["UDP query to current NS pool\nEDNS0 · TXID randomised\nDO bit set when DNSSEC validator active"]
    QUERY --> CLASSIFY

    CLASSIFY{Classify response}
    CLASSIFY -->|Answer| CNAME{"Answer is CNAME\nand qtype ≠ CNAME?"}
    CLASSIFY -->|NXDOMAIN| NX(["NXDOMAIN → client"])
    CLASSIFY -->|TC bit set| TC(["SERVFAIL — TCP fallback pending"])
    CLASSIFY -->|SERVFAIL / empty| ERR(["io::Error"])
    CLASSIFY -->|Referral| BAIL

    CNAME -->|No| ANS(["Answer → client\nTXID + RA=1 restamped"])
    CNAME -->|Yes — within CNAME budget| QUERY
    CNAME -->|CNAME budget exceeded| FAIL2(["SERVFAIL — CNAME depth"])

    BAIL{"New zone\nin-bailiwick of\ncurrent zone?"}
    BAIL -->|No| FAIL3(["SERVFAIL — bailiwick reject\ncache-poisoning defence"])
    BAIL -->|Yes| VISITED{"Zone hash\nalready in\nvisited set?"}

    VISITED -->|Yes| FAIL4(["SERVFAIL — delegation cycle"])
    VISITED -->|No| GLUE{"In-bailiwick glue\nin additional section?"}

    GLUE -->|Yes| DNSSEC
    GLUE -->|No| NS_ADDR["Recurse: resolve NS name → A / AAAA\nshares same query + depth budget"]
    NS_ADDR --> DNSSEC

    DNSSEC["DNSSEC chain step\n① DS RRset hand-off from parent referral\n② DNSKEY fetch + self-verify from child NS\nno-op when validator not installed"]
    DNSSEC --> ADVANCE["new_zone → current_zone\ndepth += 1"]
    ADVANCE --> CAPS
```

Key invariants:

- **Bailiwick**: a referral that widens the current zone is rejected outright (strict) or silently discarded (lenient), preventing cache-poisoning via off-path NS injection.
- **Cycle detection**: every visited zone is recorded as an xxh3-64 hash; a repeat hash aborts with SERVFAIL.
- **Caps**: `max_queries_per_resolution` (total outgoing UDP queries) and `max_delegation_depth` (referral hops) are checked at the top of every loop iteration.
- **Glue safety**: only glue records whose owner name sits inside the newly-delegated zone are accepted; out-of-bailiwick additional records are silently dropped.
- **DNSSEC chain**: when `[security.dnssec] enabled = true`, each delegation hop harvests the child DS from the parent referral and fetches the child's DNSKEY rrset, building the chain of trust incrementally.
