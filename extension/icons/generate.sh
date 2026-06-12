#!/usr/bin/env bash
# Generate PNG icons from icon.svg.
# Requires: inkscape (or substitute with: rsvg-convert / imagemagick)
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SVG="$SCRIPT_DIR/icon.svg"

for size in 16 32 48 128; do
  inkscape --export-type=png \
           --export-width="$size" \
           --export-height="$size" \
           --export-filename="$SCRIPT_DIR/icon-${size}.png" \
           "$SVG"
  echo "Generated icon-${size}.png"
done
