#!/bin/bash

# Change this to your router's architecture:
# Common choices: 
# - mips-unknown-linux-musl (Big Endian - Atheros)
# - mipsel-unknown-linux-musl (Little Endian - MediaTek)
# - aarch64-unknown-linux-musl (ARM 64-bit - Modern routers)
TARGET="mips-unknown-linux-musl"

echo "Building Dgaard for $TARGET..."

cross build --target $TARGET --release

# Strip the binary to make it tiny for OpenWrt flash storage
mips-linux-gnu-strip target/$TARGET/release/dgaard 2>/dev/null || \
arm-linux-gnueabi-strip target/$TARGET/release/dgaard 2>/dev/null || \
echo "Warning: Could not strip binary. It will be larger than necessary."

echo "Done. Binary location: target/$TARGET/release/dgaard"
