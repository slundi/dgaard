# Deploying a Custom Rust Binary on OpenWRT (Linksys WRT1900ACS)

## Problem

OpenWRT's root filesystem uses a read-only SquashFS overlay, which prevents writing files to most paths via SSH (Dropbear) or file transfer tools like `curl` and `wget`.

## Writable Locations

| Path | Type | Notes |
|---|---|---|
| `/tmp` | RAM tmpfs | Cleared on reboot |
| `/overlay` | SquashFS writable layer | Where `opkg` installs packages |
| `/root` | Root home directory | Normally writable |

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

Create an init script at `/etc/init.d/my-proxy`:

```sh
#!/bin/sh /etc/rc.common
START=95
start() {
    /overlay/usr/bin/my-proxy &
}
```
