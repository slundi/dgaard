# List formats

| **Format** | **Use Case** | **Example** |
|:-------|:---------|:--------|
| **Original (hosts)** | Pi-hole, hosts file | `0.0.0.0 example.com` |
| **No IP (domains)** | Some routers, simple lists | `example.com` |
| **DNSMASQ** | dnsmasq DNS server | `server=/example.com/` |
| **AdGuard** | AdGuard Home, browser extensions | `\|\|example.com^` |
