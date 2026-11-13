# Deploying a Custom Rust Binary on OpenWRT (Linksys WRT1900ACS)

## Problem

OpenWRT's root filesystem uses a read-only SquashFS overlay, which prevents writing files to most paths via SSH (Dropbear) or file transfer tools like `curl` and `wget`.

## Writable Locations

| Path       | Type                    | Notes                          |
| ---------- | ----------------------- | ------------------------------ |
| `/tmp`     | RAM tmpfs               | Cleared on reboot              |
| `/overlay` | SquashFS writable layer | Where `opkg` installs packages |
| `/root`    | Root home directory     | Normally writable              |

## Cross-Compilation

The WRT1900ACS is ARM Cortex-A9 (`armv7`). The binary must be cross-compiled for that architecture. OpenWRT does not ship glibc, so the build must target musl:

```
armv7-unknown-linux-musleabihf
```

### Using Rust directly

```bash
# Add the target
rustup target add armv7-unknown-linux-musleabihf

# Build (requires musl-cross toolchain)
cargo build --release --target armv7-unknown-linux-musleabihf
```

### Using NixOS / nix flake

```nix
pkgs.pkgsCross.armv7l-hf-multiplatform.pkgsMusl.rustPlatform.buildRustPackage
```

### Using `cross`

```bash
cargo install cross
cross build --release --target armv7-unknown-linux-musleabihf
```

## Deployment

```bash
# Copy to persistent storage
scp target/armv7-unknown-linux-musleabihf/release/my-proxy root@router:/overlay/usr/bin/

# Or copy to /tmp for testing (not persistent across reboots)
scp target/armv7-unknown-linux-musleabihf/release/my-proxy root@router:/tmp/my-proxy
ssh root@router chmod +x /tmp/my-proxy
```

## Persistence Across Reboots

Use a procd init script — dgaard ships one in [`openwrt/dgaard.init`](../openwrt/dgaard.init). Copy it to `/etc/init.d/dgaard`, then:

```bash
chmod +x /etc/init.d/dgaard
/etc/init.d/dgaard enable
/etc/init.d/dgaard start
```

procd restarts the process if it crashes and forwards its output to the system log.

## Logs

The init script sets `procd_set_param stdout 1` and `stderr 1`, so everything dgaard prints lands in logd — no log files, no flash wear:

```bash
logread -e dgaard        # recent entries
logread -f -e dgaard     # follow live
```

logd keeps a RAM ring buffer of 64 KiB by default. With `[log] queries = "all"` it wraps quickly; either stay on `"blocked"` / `"suspicious"` or enlarge it:

```bash
uci set system.@system[0].log_size=512
uci commit system
/etc/init.d/log restart
```
