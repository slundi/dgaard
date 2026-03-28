# Dgaard 🛡️

**Dgaard** is a high-performance, privacy and security focused DNS proxy written in Rust. It goes beyond simple blocklists by using Shannon Entropy, Lexical analysis, and NRD tracking to kill Malware C2 (DGA) and DNS tunneling in real-time.

## ✨ Key Features
- **DGA Detection:** Real-time Shannon Entropy and N-Gram analysis to identify randomly generated domains.
- **Stratified Filtering:** High-speed matching using Bloom Filters and FSTs for millions of rules with minimal RAM.
- **NRD Integration:** Blocks Newly Registered Domains using daily-updated feeds.
- **Behavioral Analytics:** Detects NXDOMAIN hunting and DNS exfiltration patterns.
- **OpenWrt Optimized:** Low memory footprint, zero-copy parsing, and async I/O.
- **Live Stats:** Stream binary event data over a Unix Domain Socket for real-time monitoring.

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
