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

Every DNS query passes through up to 8 stages inside `dgaard-engine`. Each stage can short-circuit to **Block** or **Allow**; otherwise the query falls through to the next stage.

```mermaid
flowchart TD
    IN([DNS Query]) --> S1

    S1["1. Fast-Drop Gatekeeper<br/>ASCII + structural validation"]
    S2["2. Zero-Copy Whitelist<br/>xxh64 hash lookup"]
    S3["3. Smart-IDN Blocker<br/>Punycode + homograph check"]
    S4["4. Tiered Blacklist<br/>Bloom filter + rkyv FSTs"]
    S5["5. Heuristic Engine<br/>Entropy · N-Gram · Lexical"]
    S6["6. Behavioral Analytics<br/>NXDOMAIN hunting + tunneling"]
    S7["7. GeoIP Scoring<br/>MaxMind MMDB lookup"]
    S8["8. Custom TI Flags<br/>16 user-defined bitflags"]

    BLOCK(["Block — return NXDOMAIN"])
    ALLOW(["Allow — proxy to upstream"])

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
        DOT["DNS-over-TLS<br/>1.1.1.1 · 8.8.8.8"]
        REC["Local recursive<br/>resolver"]
    end

    C1 -->|":53 direct"| DG
    C2 -->|":53 direct"| DG
    C3 -->|":53 via dnsmasq"| GW
    GW  -->|":5353"| DG
    DG  -->|"forwarded queries"| DOT
    DG  -->|"forwarded queries"| REC
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
