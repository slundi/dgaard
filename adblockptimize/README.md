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
