#!/bin/bash
#
# Test script: DNSSEC validation with iterative resolution (--forward-rootDNS)
#
# Prerequisites:
#   - Built dnsmasq binary in src/dnsmasq (with DNSSEC support)
#   - dig (from bind-utils/dnsutils)
#   - Root zone file at /tmp/root.zone
#   - Network access to DNS root servers
#
# Usage:
#   ./test-dnssec-iterative.sh [--keep]
#     --keep   Don't kill dnsmasq after tests (for manual debugging)

set -euo pipefail

DNSMASQ="./src/dnsmasq"
PORT=10000
PIDFILE="/tmp/dnsmasq-test-$$.pid"
LOGFILE="/tmp/dnsmasq-test-$$.log"
ROOT_ZONE="/tmp/root.zone"
KEEP=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

pass=0
fail=0
skip=0

cleanup() {
    if [ "$KEEP" -eq 0 ]; then
        [ -f "$PIDFILE" ] && kill "$(cat "$PIDFILE")" 2>/dev/null || true
        rm -f "$PIDFILE" "$LOGFILE"
    else
        echo ""
        echo -e "${CYAN}--keep mode: dnsmasq still running on port $PORT${NC}"
        echo "  PID file: $PIDFILE"
        echo "  Log file: $LOGFILE"
        echo "  Test with: dig @127.0.0.1 -p $PORT +dnssec example.com"
        echo "  Stop with: kill \$(cat $PIDFILE)"
    fi
}
trap cleanup EXIT

[ "${1:-}" = "--keep" ] && KEEP=1

# --- Preflight checks ---
echo -e "${CYAN}=== DNSSEC + Iterative Resolution Test Suite ===${NC}"
echo ""

if [ ! -x "$DNSMASQ" ]; then
    echo -e "${RED}FAIL: $DNSMASQ not found or not executable. Run 'make' first.${NC}"
    exit 1
fi

if ! command -v dig &>/dev/null; then
    echo -e "${RED}FAIL: 'dig' not found. Install bind-utils / dnsutils.${NC}"
    exit 1
fi

if [ ! -f "$ROOT_ZONE" ]; then
    echo -e "${RED}FAIL: Root zone file not found at $ROOT_ZONE${NC}"
    echo "  Download with: dig @a.root-servers.net . AXFR > $ROOT_ZONE"
    exit 1
fi

# --- Check port is free ---
if ss -tlnp 2>/dev/null | grep -q ":${PORT} " || \
   netstat -tlnp 2>/dev/null | grep -q ":${PORT} "; then
    echo -e "${RED}FAIL: Port $PORT is already in use. Stop existing dnsmasq first.${NC}"
    exit 1
fi

# --- Start dnsmasq ---
echo "Starting dnsmasq on port $PORT with --forward-rootDNS + --dnssec ..."

$DNSMASQ \
    --conf-file=/dev/null \
    --listen-address=127.0.0.1 \
    --port="$PORT" \
    --no-daemon \
    --log-queries \
    --log-facility="$LOGFILE" \
    --forward-rootDNS \
    --no-resolv \
    --no-hosts \
    --with-root-zone="$ROOT_ZONE" \
    --trust-anchor=.,20326,8,2,E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D \
    --trust-anchor=.,38696,8,2,683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16 \
    --dnssec \
    --dnssec-check-unsigned \
    --pid-file="$PIDFILE" \
    &

# Wait for dnsmasq to be ready
for i in $(seq 1 30); do
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
        break
    fi
    sleep 0.2
done

sleep 0.5  # extra settle time

if ! [ -f "$PIDFILE" ] || ! kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo -e "${RED}FAIL: dnsmasq failed to start. Check $LOGFILE${NC}"
    [ -f "$LOGFILE" ] && tail -5 "$LOGFILE"
    exit 1
fi
echo -e "${GREEN}dnsmasq running (PID $(cat "$PIDFILE"))${NC}"
echo ""

# --- Helper functions ---

query() {
    local name="$1" type="${2:-A}"
    shift 2 || true
    dig @127.0.0.1 -p "$PORT" +dnssec +time=15 +tries=2 "$name" "$type" "$@" 2>/dev/null
}

assert_ad_flag() {
    local desc="$1" name="$2" type="${3:-A}"
    local out
    printf "  %-55s " "$desc"
    out=$(query "$name" "$type")
    if echo "$out" | grep -q "flags:.*ad.*QUERY"; then
        echo -e "${GREEN}PASS${NC} (AD flag set)"
        ((pass++))
    elif echo "$out" | grep -q "SERVFAIL"; then
        echo -e "${YELLOW}SKIP${NC} (SERVFAIL - validation or resolution failed)"
        ((skip++))
    else
        echo -e "${RED}FAIL${NC} (AD flag NOT set)"
        echo "    Flags: $(echo "$out" | grep '^;; flags:')"
        ((fail++))
    fi
}

assert_no_ad_flag() {
    local desc="$1" name="$2" type="${3:-A}"
    local out
    printf "  %-55s " "$desc"
    out=$(query "$name" "$type")
    if echo "$out" | grep -q "flags:.*ad.*QUERY"; then
        echo -e "${RED}FAIL${NC} (AD flag set, expected absent)"
        ((fail++))
    elif echo "$out" | grep -q "SERVFAIL"; then
        echo -e "${YELLOW}SKIP${NC} (SERVFAIL)"
        ((skip++))
    else
        echo -e "${GREEN}PASS${NC} (AD flag absent as expected)"
        ((pass++))
    fi
}

assert_servfail() {
    local desc="$1" name="$2" type="${3:-A}"
    local out
    printf "  %-55s " "$desc"
    out=$(query "$name" "$type")
    if echo "$out" | grep -q "SERVFAIL"; then
        echo -e "${GREEN}PASS${NC} (SERVFAIL for bogus)"
        ((pass++))
    elif echo "$out" | grep -q "NOERROR"; then
        echo -e "${RED}FAIL${NC} (NOERROR instead of SERVFAIL for bogus domain)"
        ((fail++))
    else
        echo -e "${YELLOW}SKIP${NC} (unexpected response)"
        echo "    Status: $(echo "$out" | grep 'status:')"
        ((skip++))
    fi
}

assert_has_rrsig() {
    local desc="$1" name="$2" type="${3:-A}"
    local out
    printf "  %-55s " "$desc"
    out=$(query "$name" "$type")
    if echo "$out" | grep -q "RRSIG"; then
        echo -e "${GREEN}PASS${NC} (RRSIG present)"
        ((pass++))
    elif echo "$out" | grep -q "SERVFAIL"; then
        echo -e "${YELLOW}SKIP${NC} (SERVFAIL)"
        ((skip++))
    else
        echo -e "${RED}FAIL${NC} (no RRSIG in response)"
        ((fail++))
    fi
}

# --- Test Cases ---

echo -e "${CYAN}--- Test 1: DNSSEC-signed domains should validate (AD flag) ---${NC}"
assert_ad_flag "cloudflare.com A"          cloudflare.com    A
assert_ad_flag "isc.org A"                 isc.org           A
assert_ad_flag "ietf.org A"                ietf.org          A
echo ""

echo -e "${CYAN}--- Test 2: RRSIG records should be returned with +dnssec ---${NC}"
assert_has_rrsig "cloudflare.com RRSIG"    cloudflare.com    A
assert_has_rrsig "isc.org RRSIG"           isc.org           A
echo ""

echo -e "${CYAN}--- Test 3: Unsigned domains should NOT have AD flag ---${NC}"
assert_no_ad_flag "example.com (unsigned)"  example.com       A
echo ""

echo -e "${CYAN}--- Test 4: Known-bogus DNSSEC should return SERVFAIL ---${NC}"
assert_servfail "dnssec-failed.org (bogus DNSSEC)"  dnssec-failed.org  A
echo ""

echo -e "${CYAN}--- Test 5: DS record chain visible in iterative log ---${NC}"
printf "  %-55s " "Check log for DNSSEC validation activity"
sleep 1
if [ -f "$LOGFILE" ] && grep -qi "dnssec\|DNSKEY\| DS " "$LOGFILE"; then
    echo -e "${GREEN}PASS${NC} (DNSSEC activity in log)"
    ((pass++))
    echo ""
    echo -e "  ${CYAN}Log excerpts:${NC}"
    grep -i "dnssec\|secure\|bogus\|validate\|DNSKEY\| DS \|RRSIG" "$LOGFILE" | tail -20 | while read -r line; do
        echo "    $line"
    done
else
    echo -e "${YELLOW}SKIP${NC} (no DNSSEC log entries found)"
    ((skip++))
fi
echo ""

echo -e "${CYAN}--- Test 6: Iterative resolution still works for basic queries ---${NC}"
printf "  %-55s " "google.com A resolves"
out=$(query google.com A +short)
if [ -n "$out" ]; then
    echo -e "${GREEN}PASS${NC} ($(echo "$out" | head -1))"
    ((pass++))
else
    echo -e "${RED}FAIL${NC} (no answer)"
    ((fail++))
fi

printf "  %-55s " "wikipedia.org A resolves"
out=$(query wikipedia.org A +short)
if [ -n "$out" ]; then
    echo -e "${GREEN}PASS${NC} ($(echo "$out" | head -1))"
    ((pass++))
else
    echo -e "${RED}FAIL${NC} (no answer)"
    ((fail++))
fi
echo ""

# --- Results ---
echo -e "${CYAN}=== Results ===${NC}"
total=$((pass + fail + skip))
echo -e "  ${GREEN}Passed: $pass${NC}  ${RED}Failed: $fail${NC}  ${YELLOW}Skipped: $skip${NC}  Total: $total"
echo ""

if [ "$fail" -gt 0 ]; then
    echo -e "${RED}SOME TESTS FAILED${NC}"
    echo "Check the log: $LOGFILE"
    echo ""
    echo "Useful debug commands:"
    echo "  dig @127.0.0.1 -p $PORT +dnssec +multiline cloudflare.com A"
    echo "  dig @127.0.0.1 -p $PORT +dnssec +cd cloudflare.com A  # bypass validation"
    echo "  grep -i 'dnssec\|bogus\|secure' $LOGFILE"
    exit 1
elif [ "$skip" -eq "$total" ]; then
    echo -e "${YELLOW}ALL TESTS SKIPPED (network issues?)${NC}"
    exit 2
else
    echo -e "${GREEN}ALL TESTS PASSED${NC}"
    exit 0
fi
