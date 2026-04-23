# Adblockptimize

CLI tool to separate network blocking from browser blocking (CSS, JS, HTML).

Result is sorted and deduplicated.

## Usage

```bash
adblockptimize <FILES or URLs>
# split in 2 files: network_blocking.txt (domain format by default) and browser_blocking.txt

adblockptimize --no-browser --format=dnsmasq <FILES or URLs>
adblockptimize --no-network <FILES or URLs>
adblockptimize --network-file=custom.txt --browser-file=ublock_origin.txt <FILES or URLs>
```

## Targets

| Software | Domain Blocking | Wildcard Blocking | Regex Support | Whitelisting |
|:---------|:----------------|:------------------|:--------------|:-------------|
| **Pi-hole** | ✅ Yes | ✅ Yes | ✅ Yes (PCRE) | ✅ Native |
| **AdGuard Home** | ✅ Yes | ✅ Yes | ✅ Yes | ✅ Native |
| **Dnsmasq** | ✅ Yes | ✅ Yes (`address=/.../`) | ❌ No* | ⚠️ Limited |
| **Unbound** | ✅ Yes | ✅ Yes | ❌ No* | ⚠️ Limited |

* **Pi-hole & AdGuard Home**: These have a dedicated "allowlist" database that takes precedence over blocklists automatically.
* **Dnsmasq**: `address=/example.com/0.0.0.0`, it automatically blocks `sub.example.com` and `deep.sub.example.com`.
* **Unbound**: It uses `local-zone` and `local-data` directives. Setting a zone to `always_null` or `always_nxdomain` acts as a wildcard block. For whitelisting, we must manage the exclusion by ensuring the whitelist entry is more specific than the block entry.
