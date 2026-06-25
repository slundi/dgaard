#!/usr/bin/env bash
# Docker integration test for dgaard-rest.
# Builds the image, starts a container, checks every domain in demo-domains.txt
# against the /api/v1/check endpoint, and prints a pass/fail report.
#
# Usage:
#   docker/test.sh               # full run (build + test + teardown)
#   docker/test.sh --skip-build  # reuse existing image

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

# ── config ────────────────────────────────────────────────────────────────────
IMAGE="dgaard-rest-demo"
HOST_PORT=18080          # avoids colliding with anything on 8080
API="http://localhost:${HOST_PORT}"
DOMAINS_FILE="${ROOT}/demo-domains.txt"
SKIP_BUILD=false
CONTAINER_ID=""
PASS=0
FAIL=0

# ── helpers ───────────────────────────────────────────────────────────────────
info()  { echo -e "${CYAN}::${NC} $*"; }
ok()    { echo -e "${GREEN}ok${NC}"; }
die()   { echo -e "${RED}error:${NC} $*" >&2; exit 1; }

# ── parse args ────────────────────────────────────────────────────────────────
for arg in "$@"; do
    case "$arg" in
        --skip-build) SKIP_BUILD=true ;;
        *) die "unknown argument: $arg" ;;
    esac
done

# ── prerequisites ─────────────────────────────────────────────────────────────
for cmd in docker curl jq; do
    command -v "$cmd" >/dev/null 2>&1 || die "'$cmd' is required but not installed"
done
[[ -f "$DOMAINS_FILE" ]] || die "demo-domains.txt not found at $ROOT"

# ── cleanup on exit ───────────────────────────────────────────────────────────
cleanup() {
    if [[ -n "$CONTAINER_ID" ]]; then
        docker stop  "$CONTAINER_ID" >/dev/null 2>&1 || true
        docker rm    "$CONTAINER_ID" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

# ── build ─────────────────────────────────────────────────────────────────────
if [[ "$SKIP_BUILD" == false ]]; then
    info "Building ${IMAGE} (this caches deps, subsequent builds are fast)..."
    docker build -f "${ROOT}/dgaard-rest/Dockerfile" -t "$IMAGE" "$ROOT" \
        --progress=plain 2>&1 | tail -5
    ok
fi

# ── start container ───────────────────────────────────────────────────────────
info "Starting container on port ${HOST_PORT}..."
CONTAINER_ID=$(docker run --detach \
    --publish "${HOST_PORT}:8080" \
    --volume  "${ROOT}/docker:/etc/dgaard:ro" \
    "$IMAGE" \
    --config /etc/dgaard/dgaard-rest.toml)
ok

# ── wait for ready ────────────────────────────────────────────────────────────
info "Waiting for /api/v1/health..."
MAX_WAIT=30
for i in $(seq 1 $MAX_WAIT); do
    if curl --silent --fail "${API}/api/v1/health" >/dev/null 2>&1; then
        echo -e "  ${GREEN}ready${NC} (${i}s)"
        break
    fi
    if [[ $i -eq $MAX_WAIT ]]; then
        echo ""
        echo "Container logs:" >&2
        docker logs "$CONTAINER_ID" >&2
        die "service did not become healthy within ${MAX_WAIT}s"
    fi
    sleep 1
done

# ── run tests ─────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}  Results${NC}"
echo -e "  $(printf '%0.s─' {1..78})"
printf "  ${BOLD}%-44s  %-8s  %-26s  %s${NC}\n" "Domain" "Result" "Action" "Reasons"
echo -e "  $(printf '%0.s─' {1..78})"

while IFS= read -r line; do
    # Section header: lines matching "# ── <title>" → print as divider
    # Section header: "# ── <title> ───..." → print as a dim divider
    if [[ "$line" == "# ── "* ]]; then
        echo ""
        echo -e "  ${DIM}${line:3}${NC}"   # strip leading "# " (2 bytes)
        continue
    fi
    # Skip all other comments and blank lines
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ -z "${line//[[:space:]]/}" ]] && continue

    domain=$(awk '{print $1}' <<< "$line")
    expected=$(awk '{print $2}' <<< "$line")

    # POST /api/v1/check
    response=$(curl --silent --fail \
        --request POST "${API}/api/v1/check" \
        --header 'Content-Type: application/json' \
        --data "{\"domain\":\"${domain}\"}" 2>/dev/null \
        || printf '{"blocked":false,"action":"ConnectionError","reasons":[],"score":0}')

    blocked=$(jq --raw-output '.blocked'          <<< "$response")
    action=$(jq  --raw-output '.action  // "?"'   <<< "$response")
    score=$(jq   --raw-output '.score   // 0'     <<< "$response")
    reasons=$(jq --raw-output '.reasons // [] | join(", ")' <<< "$response")

    # Trim action string for display
    short_action="${action:0:24}"
    [[ ${#action} -gt 24 ]] && short_action="${short_action}…"

    # Evaluate
    if { [[ "$expected" == "blocked" && "$blocked" == "true"  ]] ||
         [[ "$expected" == "allowed" && "$blocked" == "false" ]]; }; then
        PASS=$(( PASS + 1 ))
        marker="${GREEN}✓${NC}"
        result="${GREEN}PASS${NC}"
    else
        FAIL=$(( FAIL + 1 ))
        marker="${RED}✗${NC}"
        result="${RED}FAIL${NC}  (got: $([ "$blocked" == "true" ] && echo blocked || echo allowed))"
    fi

    # Print — the marker is rendered outside the printf to avoid
    # ANSI-sequence length messing up column alignment.
    printf "  "
    echo -ne "$marker "
    printf "%-44s  " "$domain"
    echo -ne "$result"
    printf "  %-26s  %s\n" "$short_action" "$reasons"

done < "$DOMAINS_FILE"

# ── summary ───────────────────────────────────────────────────────────────────
total=$(( PASS + FAIL ))
echo ""
echo -e "  $(printf '%0.s─' {1..78})"
if [[ $FAIL -eq 0 ]]; then
    echo -e "  ${GREEN}${BOLD}All ${total} tests passed.${NC}"
else
    echo -e "  ${RED}${BOLD}${FAIL} of ${total} tests failed${NC}  (${GREEN}${PASS} passed${NC})"
fi
echo ""

# Exit non-zero so CI catches failures
[[ $FAIL -eq 0 ]]
