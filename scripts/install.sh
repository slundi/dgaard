#!/usr/bin/env bash
# install.sh — fetch a dgaard release binary from Codeberg and drop it in PATH.
#
# Quick use:
#   curl -fsSL https://codeberg.org/slundi/dgaard/raw/branch/master/scripts/install.sh | bash
#   curl -fsSL https://codeberg.org/slundi/dgaard/raw/branch/master/scripts/install.sh | bash -s -- --package dgaard-monitor
#
# Linux only. dgaard-monitor depends on inotify and unix sockets; the other
# binaries are also distributed for Linux only via this script.

set -euo pipefail

REPO="slundi/dgaard"
CODEBERG_API="https://codeberg.org/api/v1"
PACKAGE="dgaard"
VERSION=""
INSTALL_DIR=""

usage() {
  cat <<'EOF'
Usage: install.sh [--package NAME] [--version X.Y.Z] [--install-dir DIR]

Options:
  --package NAME       one of: dgaard (default), dgaard-monitor, adblockptimize
  --version X.Y.Z      install a specific version (default: latest matching tag)
  --install-dir DIR    where to drop the binary
                       (default: ~/.local/bin, or /usr/local/bin when run as root)
  -h, --help           show this help

The script picks the target triple from `uname -m`:
  x86_64  -> x86_64-unknown-linux-musl
  aarch64 -> aarch64-unknown-linux-musl
  armv7l  -> armv7-unknown-linux-musleabihf
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --package)     PACKAGE="${2:-}"; shift 2 ;;
    --version)     VERSION="${2:-}"; shift 2 ;;
    --install-dir) INSTALL_DIR="${2:-}"; shift 2 ;;
    -h|--help)     usage; exit 0 ;;
    *) echo "install.sh: unknown option '$1'" >&2; usage; exit 1 ;;
  esac
done

case "$PACKAGE" in
  dgaard|dgaard-monitor|adblockptimize) ;;
  *) echo "install.sh: unsupported --package '$PACKAGE' (expected dgaard, dgaard-monitor, or adblockptimize)" >&2; exit 1 ;;
esac

OS="$(uname -s)"
if [ "$OS" != "Linux" ]; then
  echo "install.sh: only Linux is supported (uname reports '$OS')." >&2
  echo "  dgaard-monitor uses inotify + unix sockets and isn't portable to macOS/Windows;" >&2
  echo "  the install pipeline only ships Linux musl builds for now." >&2
  exit 1
fi

case "$(uname -m)" in
  x86_64|amd64)  TARGET="x86_64-unknown-linux-musl" ;;
  aarch64|arm64) TARGET="aarch64-unknown-linux-musl" ;;
  armv7l|armv7)  TARGET="armv7-unknown-linux-musleabihf" ;;
  *) echo "install.sh: unsupported architecture '$(uname -m)'" >&2; exit 1 ;;
esac

for tool in curl tar install mktemp; do
  command -v "$tool" >/dev/null 2>&1 || { echo "install.sh: missing required tool '$tool'" >&2; exit 1; }
done

if [ -z "$INSTALL_DIR" ]; then
  if [ "$(id -u)" -eq 0 ]; then
    INSTALL_DIR="/usr/local/bin"
  else
    INSTALL_DIR="${HOME}/.local/bin"
  fi
fi

# Resolve the latest tag for the requested package when --version wasn't given.
# Codeberg's /releases endpoint returns newest-first, and the `latest` endpoint
# is global across the repo (mixes all three packages), so we filter ourselves.
if [ -z "$VERSION" ]; then
  echo "Resolving latest ${PACKAGE} release on Codeberg..." >&2
  releases_json="$(curl -fsSL -H 'Accept: application/json' \
    "${CODEBERG_API}/repos/${REPO}/releases?limit=50&page=1")"
  latest_tag="$(printf '%s' "$releases_json" \
    | tr ',{}' '\n\n\n' \
    | grep -oE '"tag_name":[[:space:]]*"[^"]+"' \
    | sed -E 's/.*"([^"]+)"$/\1/' \
    | grep -E "^${PACKAGE}-v[0-9]" \
    | head -n1 || true)"
  if [ -z "$latest_tag" ]; then
    echo "install.sh: no Codeberg release found with a tag matching '${PACKAGE}-v*'" >&2
    echo "  Check https://codeberg.org/${REPO}/releases" >&2
    exit 1
  fi
  VERSION="${latest_tag#${PACKAGE}-v}"
fi

TAG="${PACKAGE}-v${VERSION}"
ASSET="${PACKAGE}-v${VERSION}-${TARGET}.tar.gz"
URL="https://codeberg.org/${REPO}/releases/download/${TAG}/${ASSET}"

echo "Package:     ${PACKAGE}"
echo "Version:     ${VERSION}"
echo "Target:      ${TARGET}"
echo "Install dir: ${INSTALL_DIR}"
echo "Downloading  ${URL}"

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

curl -fL --proto '=https' --tlsv1.2 -o "${tmp}/${ASSET}" "${URL}"
tar -xzf "${tmp}/${ASSET}" -C "${tmp}"

if [ ! -f "${tmp}/${PACKAGE}" ]; then
  echo "install.sh: archive did not contain '${PACKAGE}' binary" >&2
  ls -la "${tmp}" >&2
  exit 1
fi

mkdir -p "${INSTALL_DIR}"
install -m 0755 "${tmp}/${PACKAGE}" "${INSTALL_DIR}/${PACKAGE}"

echo
echo "Installed ${PACKAGE} v${VERSION} -> ${INSTALL_DIR}/${PACKAGE}"

case ":${PATH-}:" in
  *":${INSTALL_DIR}:"*) ;;
  *)
    echo
    echo "Note: ${INSTALL_DIR} is not in your PATH. Add it, e.g.:"
    echo "    echo 'export PATH=\"${INSTALL_DIR}:\$PATH\"' >> ~/.profile"
    ;;
esac
