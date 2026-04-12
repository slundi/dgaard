# Cross compilation

## For OpenWRT

OpenWRT runs on several architectures. Check your router's CPU:

| Router family | Arch | Rust target |
|:--------------|:-----|:------------|
| ath79 (most Archer, etc.) | MIPS big-endian | mips-unknown-linux-musl |
| ramips (MT7620/MT7621) | MIPS little-endian | mipsel-unknown-linux-musl |
| ipq40xx / bcm53xx | ARM | armv7-unknown-linux-musleabihf |
| Raspberry Pi / RPi-CM | ARM64 | aarch64-unknown-linux-musl |
| x86/x86_64 | x86_64 | x86_64-unknown-linux-musl |



**cross** uses Docker to provide the correct cross-linker and musl sysroot automatically.

1. Install [cross](https://github.com/cross-rs/cross) `cargo install cross --git https://github.com/cross-rs/cross`
2. Build, the binary ends up at `target/<target-triple>/release/dgaard`
```shell
# Example for MIPS (ath79 — most common OpenWRT target)
cross build --target mips-unknown-linux-musl --release

# Example for MIPS little-endian (ramips)
cross build --target mipsel-unknown-linux-musl --release

# Example for ARM like a Linksys WRT1200ACS (mvebu/cortexa9)
cross build --target armv7-unknown-linux-musleabihf --release

# ARM64 such as Banana bpi r3 (mediatek/filogic)
cross build --target aarch64-unknown-linux-musl --release
```
3. Deploy to router `scp target/<target-triple>/release/dgaard root@192.168.1.1:/usr/bin/`
