# 🛡️ Dgaard: High-Performance Heuristic DNS Proxy

**Dgaard** is a next-generation DNS filtering proxy written in Rust, designed for resource-constrained environments (like OpenWrt) and high-throughput networks. Unlike traditional blockers that rely solely on static lists, Dgaard uses a **stratified filtering pipeline** combining Zero-Copy lookups, Shannon Entropy heuristics, and Smart-IDN analysis.

## ✨ Key Features
- **DGA Detection:** Real-time Shannon Entropy and N-Gram analysis to identify randomly generated domains.
- **Stratified Filtering:** High-speed matching using Bloom Filters and FSTs for millions of rules with minimal RAM.
- **NRD Integration:** Blocks Newly Registered Domains using daily-updated feeds.
- **Behavioral Analytics:** Detects NXDOMAIN hunting and DNS exfiltration patterns.
- **OpenWrt Optimized:** Low memory footprint, zero-copy parsing, and async I/O.
- **Live Stats:** Stream binary event data over a Unix Domain Socket for real-time monitoring.

## 🎯 Target Audience

* **OpenWrt & Embedded Users**: Who need a sub-10MB RAM footprint without sacrificing features.
* **Privacy Enthusiasts**: Who want to block Zero-Day malicious domains (DGA) before they are even added to public blocklists.
* **SMEs & Medium Networks**: Who require a multi-threaded, stable DNS forwarder that scales with CPU cores.
* **Security Researchers**: Who need real-time streaming of DNS events via Unix Sockets for custom monitoring.

## 💡 Motivations

Traditional DNS blockers (Pi-hole, AdGuard) have two major limitations:
1. **The "Static Gap"**: They are blind to Newly Registered Domains (NRD) and Algorithmically  Generated Domains (DGA) until a human adds them to a list.
2. **Resource Bloat**: Parsing millions of strings into memory is inefficient for routers.

**Dgaard** solves this by using rkyv (Zero-Copy) for instant list loading and Shannon Entropy math to detect suspicious patterns in real-time.

## ⚖️ Comparison with Existing Solutions

| Feature | Pi-hole / AdGuard | Blocky / Unbound | Dgaard |
| **Language** | PHP/Go/C | Go / C | **Rust** (Memory Safe & Fast) |
| **Filtering Method** | Exact Match Lists | Lists + RegEx | **Stratified: Lists + Heuristics + IDN** |
| **RAM Usage** | Moderate to High | Moderate | **Ultra-Low (Bloom Filters & rkyv)** |
| **DGA Detection** | ❌ No | ❌ No | **✅ Yes (Shannon Entropy Math)** |
| **IDN/Homograph** | ⚠️ Partial | ❌ No | **✅ Yes (Punycode Analysis)** |
| **Architecture** | Monolithic (UI+Core) | Core Only | **Split-Process (Engine + Unix Socket UI)** |
| **Enterprise Scale** | ❌ Hard to scale | ✅ Possible | **✅ Built-in SO_REUSEPORT support** |

### Comparison with Proprietary Solutions (Cisco Umbrella / NextDNS)

* **Privacy**: Unlike cloud providers, Dgaard keeps 100% of your data on your local hardware. No logs ever leave your network.
* **Cost**: Enterprise-grade DGA detection usually requires a monthly subscription. Dgaard provides it for free as an open-source tool.
* **Latency**: Dgaard runs at your network edge (router), eliminating the RTT (Round Trip Time) to cloud-based filtering servers.

## 🛠️ The Stratified Filtering Pipeline

Dgaard processes every query through a "Short-Circuit" funnel to ensure maximum speed:
* **Fast-Drop Gatekeeper**: Instantly rejects non-standard ASCII/malformed domains.
* **Zero-Copy Whitelist**: Bypasses all checks for your trusted domains using `xxh64` hashes.
* **Smart-IDN Blocker**: Decodes Punycode and blocks Homograph (look-alike) phishing attacks.
* **Tiered Blacklist**: Massive 1M+ entry lists stored in Bloom Filters and rkyv archives (0.1ms lookup).
* **Heuristic Engine**: Calculates the entropy of the domain. High-randomness strings (e.g. `ajh12-v9z.top`) are blocked as potential malware C2 channels.

## 🚀 Technical Highlights

* **Zero-Copy Serialization**: Uses `rkyv` to map massive blocklists from disk directly into memory.
* **Async Core**: Powered by `Tokio` for high-concurrency UDP handling.
* **Telemetry**: Streams real-time `Postcard`-encoded events over a Unix Domain Socket (UDS) for external Dashboards/TUIs.
* **Atomic Updates**: Uses `arc-swap` for zero-downtime rule updates.

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

* Primary Repo: [Codeberg main repo](https://codeberg.org/slundi/dgaard)
* Mirror: [GitHub repo](https://codeberg.com/slundi/dgaard)

Dgaard: Guarding your gateway with Rust-powered intelligence.
