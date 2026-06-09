#!/usr/bin/env bash
# openwrt/opkg/build-ipk.sh — assemble dgaard_VERSION_ARCH.ipk
# Usage: bash build-ipk.sh <version> <arch>
# Must be run from its own directory (openwrt/opkg/) or via `just package`.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PKG_DATA="$SCRIPT_DIR/pkg/data"

VERSION="${1:-0.1.0}"
ARCH="${2:-arm_cortex-a9_vfpv3}"
TARGET="armv7-unknown-linux-musleabihf"
PKG_NAME="dgaard"
OUT="${PKG_NAME}_${VERSION}_${ARCH}.ipk"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

echo "→ Preparing data tree..."
mkdir -p "$WORK/data/usr/bin"
mkdir -p "$WORK/data/etc/dgaard"
mkdir -p "$WORK/data/etc/init.d"
mkdir -p "$WORK/data/usr/lib/lua/luci/controller"
mkdir -p "$WORK/data/www/luci-static/resources/view"
mkdir -p "$WORK/data/usr/share/rpcd/acl.d"
mkdir -p "$WORK/data/usr/libexec/rpcd"

# Binary (built at repo root by `just build`)
cp "$REPO_ROOT/target/${TARGET}/release/${PKG_NAME}" "$WORK/data/usr/bin/"
chmod 755 "$WORK/data/usr/bin/${PKG_NAME}"

# Default config template (postinst copies this to config.toml on first install)
cp "$REPO_ROOT/config.example.toml" "$WORK/data/etc/dgaard/config.example.toml"

# init.d
cp "$PKG_DATA/etc/init.d/dgaard" "$WORK/data/etc/init.d/dgaard"
chmod 755 "$WORK/data/etc/init.d/dgaard"

# rpcd handler
cp "$PKG_DATA/usr/libexec/rpcd/dgaard" "$WORK/data/usr/libexec/rpcd/dgaard"
chmod 755 "$WORK/data/usr/libexec/rpcd/dgaard"

# rpcd ACL
cp "$PKG_DATA/usr/share/rpcd/acl.d/dgaard.json" "$WORK/data/usr/share/rpcd/acl.d/dgaard.json"

# LuCI controller
cp "$PKG_DATA/usr/lib/lua/luci/controller/dgaard.lua" \
    "$WORK/data/usr/lib/lua/luci/controller/dgaard.lua"

# LuCI view
cp "$PKG_DATA/www/luci-static/resources/view/dgaard.js" \
    "$WORK/data/www/luci-static/resources/view/dgaard.js"

echo "→ Writing control file..."
mkdir -p "$WORK/control"
cat > "$WORK/control/control" <<EOF
Package: $PKG_NAME
Version: $VERSION
Architecture: $ARCH
Maintainer: Your Name <you@example.com>
Description: Dgaard DNS proxy with DGA/entropy detection and parental control
Depends: libc
EOF

# conffiles — these won't be overwritten on upgrade
cat > "$WORK/control/conffiles" <<EOF
/etc/dgaard/config.toml
EOF

# postinst — first-install setup
cat > "$WORK/control/postinst" <<'EOF'
#!/bin/sh
# Create config from example only on first install
if [ ! -f /etc/dgaard/config.toml ] && [ -f /etc/dgaard/config.example.toml ]; then
    cp /etc/dgaard/config.example.toml /etc/dgaard/config.toml
    echo "dgaard: created default /etc/dgaard/config.toml"
fi
mkdir -p /var/run/dgaard /var/dgaard
/etc/init.d/dgaard enable
/etc/init.d/rpcd restart
exit 0
EOF
chmod 755 "$WORK/control/postinst"

cat > "$WORK/control/prerm" <<'EOF'
#!/bin/sh
/etc/init.d/dgaard stop 2>/dev/null || true
/etc/init.d/dgaard disable 2>/dev/null || true
/etc/init.d/rpcd restart 2>/dev/null || true
exit 0
EOF
chmod 755 "$WORK/control/prerm"

echo "→ Building archives..."
tar -czf "$WORK/control.tar.gz" -C "$WORK/control" .
tar -czf "$WORK/data.tar.gz"    -C "$WORK/data"    .
echo "2.0" > "$WORK/debian-binary"

echo "→ Assembling .ipk..."
ar r "$OUT" "$WORK/debian-binary" "$WORK/control.tar.gz" "$WORK/data.tar.gz"

echo "✓ Built: $OUT ($(du -sh "$OUT" | cut -f1))"
