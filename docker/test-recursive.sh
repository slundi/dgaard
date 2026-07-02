#!/usr/bin/env bash
# Podman integration test for dgaard in recursive DNS mode.
# Builds the dgaard image, starts a container, sends real DNS queries via dig,
# and checks NXDOMAIN for blocked domains and NOERROR for clean ones.
#
# Requirements:
#   - podman (rootless or root)
#   - dig   (from bind-utils / dnsutils)
#   - outbound UDP port 53 reachable from the container (for the "noerror" tests)
#
# Usage:
#   docker/test-recursive.sh               # full run (build + test + teardown)
#   docker/test-recursive.sh --skip-build  # reuse existing image

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

# ── config ────────────────────────────────────────────────────────────────────
IMAGE="dgaard-demo"
# Port on the host that forwards to 5353/udp inside the container.
# Chosen high to avoid colliding with any local DNS service.
HOST_PORT=15353
DNS_ADDR="127.0.0.1"
DOMAINS_FILE="${ROOT}/docker/recursive-domains.txt"
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
for cmd in podman dig; do
    command -v "$cmd" >/dev/null 2>&1 || die "'$cmd' is required but not installed"
done
[[ -f "$DOMAINS_FILE" ]] || die "recursive-domains.txt not found at $ROOT/docker/"

# ── cleanup on exit ───────────────────────────────────────────────────────────
cleanup() {
    if [[ -n "$CONTAINER_ID" ]]; then
        podman stop "$CONTAINER_ID" >/dev/null 2>&1 || true
        podman rm   "$CONTAINER_ID" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

# ── build ─────────────────────────────────────────────────────────────────────
if [[ "$SKIP_BUILD" == false ]]; then
    info "Building ${IMAGE} from dgaard/Dockerfile..."
    podman build -f "${ROOT}/dgaard/Dockerfile" -t "$IMAGE" "$ROOT" \
        --progress=plain 2>&1 | tail -5
    ok
fi

# ── start container ───────────────────────────────────────────────────────────
info "Starting container on UDP port ${HOST_PORT}..."
CONTAINER_ID=$(podman run --detach \
    --publish "${HOST_PORT}:5353/udp" \
    --volume  "${ROOT}/docker:/etc/dgaard:ro" \
    "$IMAGE" \
    --config /etc/dgaard/dgaard-recursive.toml)
ok

# ── wait for ready ────────────────────────────────────────────────────────────
# Probe with a blocklisted domain — no internet needed, instant NXDOMAIN.
info "Waiting for DNS server to respond..."
MAX_WAIT=30
for i in $(seq 1 $MAX_WAIT); do
    probe=$(dig +time=2 +tries=1 \
        @${DNS_ADDR} -p ${HOST_PORT} malware-c2-demo.com A 2>/dev/null \
        | grep -oE 'status: [A-Z]+' | head -1 | awk '{print $2}' || true)
    if [[ "$probe" == "NXDOMAIN" ]]; then
        echo -e "  ${GREEN}ready${NC} (${i}s)"
        break
    fi
    if [[ $i -eq $MAX_WAIT ]]; then
        echo ""
        echo "Container logs:" >&2
        podman logs "$CONTAINER_ID" >&2
        die "service did not become healthy within ${MAX_WAIT}s"
    fi
    sleep 1
done

# ── run tests ─────────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}  Results${NC}"
echo -e "  $(printf '%0.s─' {1..70})"
printf "  ${BOLD}%-44s  %-6s  %-10s  %s${NC}\n" "Domain" "Result" "Expected" "Got"
echo -e "  $(printf '%0.s─' {1..70})"

while IFS= read -r line; do
    # Section header: "# ── <title> ───..." → print as dim divider
    if [[ "$line" == "# ── "* ]]; then
        echo ""
        echo -e "  ${DIM}${line:3}${NC}"
        continue
    fi
    # Skip all other comments and blank lines
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ -z "${line//[[:space:]]/}" ]] && continue

    domain=$(awk '{print $1}' <<< "$line")
    expected=$(awk '{print $2}' <<< "$line")

    # Query the DNS server and extract the RCODE from the ;; ->>HEADER<<- line.
    # Full output is kept so grep can find "status: NOERROR" regardless of
    # which dig version or display flags are active.
    dig_out=$(dig +time=10 +tries=1 \
        @${DNS_ADDR} -p ${HOST_PORT} "${domain}" A 2>/dev/null || true)
    status=$(echo "$dig_out" \
        | grep -oE 'status: [A-Z]+' | head -1 \
        | awk '{print $2}' | tr '[:upper:]' '[:lower:]' || true)
    [[ -z "$status" ]] && status="timeout"

    # Evaluate result
    if [[ "$status" == "$expected" ]]; then
        PASS=$(( PASS + 1 ))
        marker="${GREEN}✓${NC}"
        result_str="${GREEN}PASS${NC}  "
    else
        FAIL=$(( FAIL + 1 ))
        marker="${RED}✗${NC}"
        result_str="${RED}FAIL${NC}  "
    fi

    printf "  "
    echo -ne "$marker "
    printf "%-44s  " "$domain"
    echo -ne "$result_str"
    printf "%-10s  %s\n" "$expected" "$status"

done < "$DOMAINS_FILE"

# ── summary ───────────────────────────────────────────────────────────────────
total=$(( PASS + FAIL ))
echo ""
echo -e "  $(printf '%0.s─' {1..70})"
if [[ $FAIL -eq 0 ]]; then
    echo -e "  ${GREEN}${BOLD}All ${total} tests passed.${NC}"
else
    echo -e "  ${RED}${BOLD}${FAIL} of ${total} tests failed${NC}  (${GREEN}${PASS} passed${NC})"
fi
echo ""

# Exit non-zero so CI catches failures
[[ $FAIL -eq 0 ]]
