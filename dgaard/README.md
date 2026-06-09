# 🛡️ Dgaard: High-Performance Heuristic DNS Proxy

**Dgaard** is a next-generation DNS filtering proxy written in Rust, designed for resource-constrained environments (like OpenWrt) and high-throughput networks. Unlike traditional blockers that rely solely on static lists, Dgaard uses a **stratified filtering pipeline** combining Zero-Copy lookups, Shannon Entropy heuristics, and Smart-IDN analysis.

## ✨ Key Features

- **DGA Detection:** Real-time Shannon Entropy and N-Gram analysis to identify randomly generated domains.
- **Stratified Filtering:** High-speed matching using Bloom Filters and FSTs for millions of rules with minimal RAM.
- **NRD Integration:** Blocks Newly Registered Domains using daily-updated feeds.
- **Behavioral Analytics:** Detects NXDOMAIN hunting and DNS exfiltration patterns.
- **Smart Keyword Sentry**: Proactive [parental control](docs/Parental-control.md) using `Aho-Corasick` label-matching to block categories (Adult, Gambling) with near-zero memory footprint, avoiding common over-blocking issues.
- **OpenWrt Optimized:** Low memory footprint, zero-copy parsing, and async I/O.
- **Live Stats:** Stream binary event data over a Unix Domain Socket for real-time monitoring.
- **Deep Packet Inspection (DPI Lite)**: Analyzes TXT record entropy and CNAME chains to stop data exfiltration and CNAME cloaking.
- **DNS Rebinding Protection**: Automatically drops public queries resolving to private local IPs.
- **Threat Intelligence**: Analyzes blocklist trends to provide users with data-driven suggestions for parental control and TLD blocking.
- **GeoIP Suspicion Scoring**: Checks each resolved IP against a local MaxMind-format MMDB database. Responses from high-risk jurisdictions add configurable points to the domain's threat score, amplifying existing signals (entropy, NRD, low TTL) to catch brand-new malware infrastructure before it appears on any public blocklist.
- **Custom Threat-Intelligence Flags** _(requires `custom_flags` feature)_: Map up to 16 organisation-specific domain lists (AI-generated feeds, sector threat intel, proprietary sources) to named bitflags in the telemetry stream. Each flag carries its own suspicion weight, enabling sector-specific threat models without modifying the engine.

## 🎯 Target Audience

- **OpenWrt & Embedded Users**: Who need a sub-10MB RAM footprint without sacrificing features.
- **Privacy Enthusiasts**: Who want to block Zero-Day malicious domains (DGA) before they are even added to public blocklists.
- **SMEs & Medium Networks**: Who require a multi-threaded, stable DNS forwarder that scales with CPU cores.
- **Security Researchers**: Who need real-time streaming of DNS events via Unix Sockets for custom monitoring.

## 💡 Motivations

Traditional DNS blockers (Pi-hole, AdGuard) have two major limitations:

1. **The "Static Gap"**: They are blind to Newly Registered Domains (NRD) and Algorithmically Generated Domains (DGA) until a human adds them to a list.
2. **Resource Bloat**: Parsing millions of strings into memory is inefficient for routers.

**Dgaard** solves this by using rkyv (Zero-Copy) for instant list loading and Shannon Entropy math to detect suspicious patterns in real-time.

## ⚖️ Comparison with Existing Solutions

| Feature              | Pi-hole / AdGuard    | Blocky / Unbound | Dgaard                                      |
| :------------------- | :------------------- | :--------------- | :------------------------------------------ |
| **Language**         | PHP/Go/C             | Go / C           | **Rust** (Memory Safe & Fast)               |
| **Filtering Method** | Exact Match Lists    | Lists + RegEx    | **Stratified: Lists + Heuristics + IDN**    |
| **RAM Usage**        | Moderate to High     | Moderate         | **Ultra-Low (Bloom Filters & rkyv)**        |
| **DGA Detection**    | ❌ No                | ❌ No            | **✅ Yes (Shannon Entropy Math)**           |
| **IDN/Homograph**    | ⚠️ Partial            | ❌ No            | **✅ Yes (Punycode Analysis)**              |
| **Architecture**     | Monolithic (UI+Core) | Core Only        | **Split-Process (Engine + Unix Socket UI)** |
| **Enterprise Scale** | ❌ Hard to scale     | ✅ Possible      | **✅ Built-in SO_REUSEPORT support**        |
| **GeoIP Scoring**    | ❌ No                | ❌ No            | **✅ Yes (MMDB, configurable weight)**      |
| **Custom TI Flags**  | ❌ No                | ❌ No            | **✅ Yes (`custom_flags` feature)**         |

### Comparison with Proprietary Solutions (Cisco Umbrella / NextDNS)

- **Privacy**: Unlike cloud providers, Dgaard keeps 100% of your data on your local hardware. No logs ever leave your network.
- **Cost**: Enterprise-grade DGA detection usually requires a monthly subscription. Dgaard provides it for free as an open-source tool.
- **Latency**: Dgaard runs at your network edge (router), eliminating the RTT (Round Trip Time) to cloud-based filtering servers.

## 🛠️ The Stratified Filtering Pipeline

Dgaard processes every query through a "Short-Circuit" funnel to ensure maximum speed:

- **Fast-Drop Gatekeeper**: Instantly rejects non-standard ASCII/malformed domains.
- **Zero-Copy Whitelist**: Bypasses all checks for your trusted domains using `xxh64` hashes.
- **Smart-IDN Blocker**: Decodes Punycode and blocks Homograph (look-alike) phishing attacks.
- **Tiered Blacklist**: Massive 1M+ entry lists stored in Bloom Filters and rkyv archives (0.1ms lookup).
- **Heuristic Engine**: Calculates the entropy of the domain. High-randomness strings (e.g. `ajh12-v9z.top`) are blocked as potential malware C2 channels.

## 🚀 Technical Highlights

- **Zero-Copy Serialization**: Uses `rkyv` to map massive blocklists from disk directly into memory.
- **Async Core**: Powered by `Tokio` for high-concurrency UDP handling.
- **Telemetry**: Streams real-time `Postcard`-encoded events over a Unix Domain Socket (UDS) for external Dashboards/TUIs.
- **Atomic Updates**: Uses `arc-swap` for zero-downtime rule updates.

## 🌍 GeoIP Suspicion Scoring

Nation-state threat actors, ransomware operators, and botnet C2 infrastructure are disproportionately hosted in jurisdictions with limited law enforcement cooperation. Blocklisting individual domains is a reactive game — infrastructure rotates faster than public lists update. GeoIP scoring provides a structural defence: any domain — regardless of whether it has been seen before — that resolves to flagged infrastructure accumulates suspicion points.

**How it works:**

After a successful upstream DNS resolution, Dgaard queries a local MaxMind-format MMDB database (opened with `mmap` to minimise RAM on OpenWrt) for each returned A/AAAA address. If the IP maps to a listed country code, `suspicious_country_score` points are added to the domain's running total. The check never blocks by itself; it amplifies other signals:

- A domain with `score 6` (entropy + NRD) resolving to a CN-hosted IP (+3) crosses the default blocking threshold of 10 automatically.
- An SME with no business in RU, CN, KP, or IR can suppress an entire class of infrastructure threats without false-positive risk for legitimate CDN traffic.
- When `log_suspicious = true`, GeoIP events appear in the telemetry stream even when the domain is forwarded, enabling SIEM correlation without modifying blocking policy.

**MMDB database sources (free):**

| Source           | URL                                                           |
| ---------------- | ------------------------------------------------------------- |
| MaxMind GeoLite2 | <https://www.maxmind.com/en/geolite-free-ip-geolocation-data> |
| DB-IP            | <https://db-ip.com/db/>                                       |
| ip2location      | <https://www.ip2location.com/database>                        |

```toml
[security.geo_ip]
enabled = true
database_path = "/etc/dgaard/GeoLite2-Country.mmdb"
# ISO 3166-1 alpha-2 codes
suspicious_countries = ["RU", "CN", "KP", "IR"]
# 3 = suspicious signal; set to 10 for hard-block in high-security environments
suspicious_country_score = 3
```

---

## 🏷️ Custom Threat-Intelligence Flags _(requires `custom_flags` feature)_

Different organisations face different threat profiles. A financial institution's threat feed differs from a healthcare provider's or a manufacturing plant's. The `custom_flags` feature lets each deployment consume sector-specific domain intelligence — large AI-generated lists, proprietary feeds, curated research datasets — as first-class telemetry signals, without forking the engine.

**How it works:**

`StatBlockReason` is widened from `u16` to `u32`. Bits 0–15 are the built-in engine flags. Bits 16–31 are user-defined: each entry in `[[security.custom_flags]]` binds a bit index to a plain-text domain list file, a human name, a short code, and a suspicion score contribution. At startup (and on `SIGHUP` reload) the list is loaded and registered as a filter source tagged with that bit. A domain hit sets the bit in the event's `StatBlockReason` and adds the configured score.

Custom flag names and codes propagate through the Unix socket event stream alongside built-in flags, so `dgaard-monitor` and any connected SIEM receive source attribution automatically — no dashboard changes required.

**Security argument:** Large AI-generated classification datasets (hundreds of thousands of domains) can be loaded as a single custom flag. The bit persists in every telemetry event for that domain, giving analysts the ability to filter or pivot on the source in post-processing — something not possible with a flat blocklist hit.

**Use cases by sector:**

| Sector     | List type                            | Flag code      | Score        |
| ---------- | ------------------------------------ | -------------- | ------------ |
| Finance    | AI-generated fraud/phishing domains  | `FRAUD_DOMAIN` | 6            |
| Healthcare | Credential-harvesting infrastructure | `HEALTH_PHISH` | 8            |
| Enterprise | Cryptocurrency mining pool endpoints | `CRYPTO_POOL`  | 4            |
| Research   | Known honeypot / sinkhole domains    | `HONEYPOT`     | 8            |
| Any        | Proprietary internal threat feed     | `INTERNAL_TI`  | configurable |

```toml
# Compile with: cargo build --features custom_flags

[[security.custom_flags]]
bit = 16
code = "AI_FRAUD"
name = "AI-Detected Fraud Domain"
description = "Domains flagged by the AI-generated financial fraud classification list."
suspicious_score = 6
list_path = "/etc/dgaard/fraud-domains.txt"

[[security.custom_flags]]
bit = 17
code = "CRYPTO_POOL"
name = "Cryptocurrency Mining Pool"
description = "Known mining pool and cryptojacking endpoints."
suspicious_score = 4
list_path = "/etc/dgaard/crypto-mining.txt"
```

Valid bit range: 16–31. Maximum 16 custom flags. Duplicate or out-of-range bit values are rejected at config parse time.

---

## 🚀 Quick Start (OpenWrt)

1. **Install Dependencies:**

Ensure you have `ca-bundle` and `libstdcpp` installed.

2. **Download Binary:**

Place the `dgaard` binary in `/usr/bin/` and `dgaard.toml` in `/etc/dgaard/`.

3. **Configure Dnsmasq:**

Point your local dnsmasq to Dgaard (default port 5353):

```bash
# in OpenWRT
uci set dhcp.@dnsmasq[0].server='127.0.0.1#5353'
uci commit dhcp
/etc/init.d/dnsmasq restart
```

4. **Run**

```bash
dgaard --config /etc/dgaard/dgaard.toml
```

## 🛠️ Configuration

Dgaard uses a stratified filtering order to maximize performance:

1. Whitelist (Instant pass)
2. Hot Cache (Favorites/Frequently used)
3. Static Blocklists (Exact/Wildcard/Regex)
4. Heuristic Engine (Entropy/Lexical/NRD)
   See [dgaard.toml](config.example.toml) for detailed options.

## 📊 Monitoring

Connect to the Unix socket to see live hits:

```bash
socat - UNIX-CONNECT:/tmp/dgaard_stats.sock
```

## Build & deploy

```bash
cargo build --release

# cross compilation
cargo install cross --git https://github.com/cross-rs/cross

# Deploy to your router
# Move binary
scp target/mips-unknown-linux-musl/release/dgaard root@192.168.1.1:/usr/bin/

# Move config
scp dgaard.toml root@192.168.1.1:/etc/dgaard.toml

# Run it!
ssh root@192.168.1.1 "dgaard /etc/dgaard.toml"
```

Set permissions:

```bash
# Make it executable
chmod +x /etc/init.d/dgaard

# Enable it to start on boot
/etc/init.d/dgaard enable

# Start it now
/etc/init.d/dgaard start
```

## 🤝 Contributing

Dgaard is developed on Codeberg and mirrored to GitHub.

- Primary Repo: [Codeberg main repo](https://codeberg.org/slundi/dgaard)
- Mirror: [GitHub repo](https://codeberg.com/slundi/dgaard)

Dgaard: Guarding your gateway with Rust-powered intelligence.
