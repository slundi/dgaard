#!/usr/bin/env bash
# Build dist/dgaard-configurator.html: one self-contained file that works from
# file:// (ES modules are blocked by CORS there) and on any static host.
#
# This is deliberately not a bundler. The modules are concatenated in
# dependency order after stripping their `import` lines and `export` keywords,
# which is safe because every module in js/ sticks to two rules:
#   * imports are single-line `import { … } from './x.js';`
#   * exports are inline (`export const` / `export function` / `export class`),
#     never `export { … }` lists and never `export default`.
# check_module_discipline() below enforces both, so a future module that breaks
# them fails the build instead of producing a silently broken page.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT/dist"
OUT="$OUT_DIR/dgaard-configurator.html"

# Dependency order: a module may only use names defined above it at load time.
MODULES=(
  js/theme.js
  js/store.js
  js/widgets.js
  js/toml-emit.js
  js/schema/monitor.js
  js/schema/engine.js
  js/render.js
  js/main.js
)

check_module_discipline() {
  local failed=0
  for module in "${MODULES[@]}"; do
    if grep -nE '^\s*export\s+(default|\{)' "$ROOT/$module"; then
      echo "error: $module uses an export form the build cannot inline" >&2
      failed=1
    fi
    if grep -nE '^\s*import\s' "$ROOT/$module" | grep -vE "^[0-9]+:\s*import .* from '[^']+';$"; then
      echo "error: $module has an import the build cannot strip" >&2
      failed=1
    fi
  done
  [ "$failed" -eq 0 ] || exit 1
}

inline_module() {
  printf '\n// ── %s %s\n' "$1" "$(printf '─%.0s' $(seq 1 $((60 - ${#1}))))"
  sed -E \
    -e "/^\s*import .* from '[^']+';$/d" \
    -e 's/^export (const|let|var|function|class|async function) /\1 /' \
    "$ROOT/$1"
}

check_module_discipline
mkdir -p "$OUT_DIR"

while IFS= read -r line; do
  case "$line" in
    *'href="css/style.css"'*)
      printf '  <style>\n'
      cat "$ROOT/css/style.css"
      printf '  </style>\n'
      ;;
    *'src="js/main.js"'*)
      printf '  <script>\n'
      for module in "${MODULES[@]}"; do inline_module "$module"; done
      printf '  </script>\n'
      ;;
    *)
      printf '%s\n' "$line"
      ;;
  esac
done < "$ROOT/index.html" > "$OUT"

printf 'built %s (%s)\n' "$OUT" "$(du -h "$OUT" | cut -f1)"
