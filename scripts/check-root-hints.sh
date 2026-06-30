#!/usr/bin/env bash
#
# Operational drift-check for the compiled-in root-server hints.
#
# - Downloads `named.root` from IANA.
# - Hands it to the `upstream_root_hints_match_compiled_constants` test
#   via the `DGAARD_NAMED_ROOT` environment variable.
# - Exits non-zero (with a human-readable diff) when the compiled-in
#   `ROOT_HINTS_V4` / `ROOT_HINTS_V6` arrays have drifted.
#
# Invoked from `just check-root-hints` and from the weekly Woodpecker
# cron in `.woodpecker.yml`. See `CONTRIBUTING.md` for the manual
# regeneration procedure.

set -euo pipefail

NAMED_ROOT_URL="${NAMED_ROOT_URL:-https://www.internic.net/domain/named.root}"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

NAMED_ROOT_FILE="$WORKDIR/named.root"

echo "==> Downloading $NAMED_ROOT_URL"
# `curl -fSL` fails on HTTP errors, follows redirects, and shows
# transfer errors but suppresses the progress bar. `-o` writes to a
# fixed path so we can hand it to the test below.
curl -fSL --retry 3 --retry-delay 5 -o "$NAMED_ROOT_FILE" "$NAMED_ROOT_URL"

echo "==> Running compiled-vs-upstream drift check"
# Pin the test name so the runner doesn't get confused by other tests
# that happen to share a prefix. `--no-fail-fast` would let other
# unrelated test failures surface, but for a focused drift check we
# want the bail-on-first behaviour `cargo nextest` defaults to.
DGAARD_NAMED_ROOT="$NAMED_ROOT_FILE" \
    cargo nextest run \
    -p dgaard \
    --no-capture \
    'dns::recursive::tests::upstream_root_hints_match_compiled_constants'

echo "==> Root hints in sync with $NAMED_ROOT_URL"
