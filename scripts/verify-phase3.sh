#!/usr/bin/env bash
#
# verify-phase3.sh - Phase 3 Verification
#
# Tests that POL-02 (per-device destination allowlists) is deployed
# correctly and the allowlist infrastructure is functional.
#
# Usage: sudo ./verify-phase3.sh

set -euo pipefail

BRIDGE_IP="192.168.50.1"
RYU_API="http://127.0.0.1:8080"
PASS=0
FAIL=0
WARN=0

pass() { echo "  [PASS] $1"; PASS=$((PASS + 1)); }
fail() { echo "  [FAIL] $1"; FAIL=$((FAIL + 1)); }
warn() { echo "  [WARN] $1"; WARN=$((WARN + 1)); }
section() { echo ""; echo "== $1 =="; }

# -- Preflight --

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root (sudo)."
    exit 1
fi

echo "Phase 3 Verification: Per-Device Destination Allowlists (POL-02)"
echo "$(date)"

# -- 1. Ryu Container Status --

section "Ryu Policy App: Container"

RYU_STATE=$(docker inspect --format '{{.State.Status}}' ryu-controller 2>/dev/null || echo "not found")
if [ "$RYU_STATE" = "running" ]; then
    pass "Ryu container is running"
else
    fail "Ryu container is not running (state: $RYU_STATE)"
    echo "  Cannot proceed without Ryu. Check: docker logs ryu-controller"
    exit 1
fi

RYU_LOGS=$(docker logs ryu-controller 2>&1 | tail -50)
if echo "$RYU_LOGS" | grep -q "Policy rules installed"; then
    pass "Gateway policy app loaded and rules installed"
else
    fail "Gateway policy app does not appear to have installed rules"
fi

# -- 2. Policy REST API: Core Status --

section "Ryu Policy App: REST API (Core)"

STATUS_RESPONSE=$(curl -s --max-time 5 "$RYU_API/policy/status" 2>/dev/null || echo "FAILED")
if [ "$STATUS_RESPONSE" = "FAILED" ]; then
    fail "Policy REST API is not responding"
    exit 1
else
    pass "Policy REST API is responding"

    SWITCH_CONNECTED=$(echo "$STATUS_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('switch_connected', False))" 2>/dev/null || echo "unknown")
    RULES_INSTALLED=$(echo "$STATUS_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('rules_installed', False))" 2>/dev/null || echo "unknown")
    RULE_COUNT=$(echo "$STATUS_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('rule_count', 0))" 2>/dev/null || echo "0")

    if [ "$SWITCH_CONNECTED" = "True" ]; then
        pass "OVS switch is connected to Ryu"
    else
        fail "OVS switch is NOT connected to Ryu"
    fi

    if [ "$RULES_INSTALLED" = "True" ]; then
        pass "Proactive rules are installed ($RULE_COUNT rules)"
    else
        fail "Proactive rules are NOT installed"
    fi
fi

# -- 3. Phase 3: Allowlist Configuration --

section "Phase 3: Allowlist Configuration"

# Check enforcement mode.
ENF_MODE=$(echo "$STATUS_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('enforcement_mode', 'unknown'))" 2>/dev/null || echo "unknown")
if [ "$ENF_MODE" = "learning" ] || [ "$ENF_MODE" = "enforcing" ]; then
    pass "Enforcement mode: $ENF_MODE"
else
    fail "Enforcement mode is unexpected: $ENF_MODE"
fi

# Check profiled devices count.
PROFILED=$(echo "$STATUS_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('profiled_devices', 0))" 2>/dev/null || echo "0")
if [ "$PROFILED" -gt 0 ]; then
    pass "$PROFILED device(s) have allowlist profiles loaded"
else
    warn "No device profiles loaded. Create device_profiles.json and reload."
fi

# Check DNS cache.
DNS_ENTRIES=$(echo "$STATUS_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('dns_cache_entries', 0))" 2>/dev/null || echo "0")
if [ "$DNS_ENTRIES" -gt 0 ]; then
    pass "DNS cache has $DNS_ENTRIES entries"
else
    warn "DNS cache is empty. The dns_cache_updater service may not be running yet."
fi

# -- 4. Allowlists REST Endpoint --

section "Phase 3: Allowlist REST Endpoints"

ALLOWLIST_RESPONSE=$(curl -s --max-time 5 "$RYU_API/policy/allowlists" 2>/dev/null || echo "FAILED")
if [ "$ALLOWLIST_RESPONSE" = "FAILED" ]; then
    fail "GET /policy/allowlists is not responding"
else
    pass "GET /policy/allowlists is responding"

    AL_TOTAL=$(echo "$ALLOWLIST_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('total_profiles', 0))" 2>/dev/null || echo "0")
    pass "Allowlists endpoint reports $AL_TOTAL profile(s)"
fi

# Test the reload endpoint (just check it responds, do not actually change anything).
RELOAD_RESPONSE=$(curl -s --max-time 5 -X POST "$RYU_API/policy/allowlists/reload" 2>/dev/null || echo "FAILED")
if [ "$RELOAD_RESPONSE" = "FAILED" ]; then
    fail "POST /policy/allowlists/reload is not responding"
else
    RELOAD_SUCCESS=$(echo "$RELOAD_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('success', False))" 2>/dev/null || echo "unknown")
    if [ "$RELOAD_SUCCESS" = "True" ]; then
        pass "POST /policy/allowlists/reload works"
    else
        fail "POST /policy/allowlists/reload returned success=false"
    fi
fi

# Test the DNS cache GET endpoint.
DNS_CACHE_RESPONSE=$(curl -s --max-time 5 "$RYU_API/policy/dns-cache" 2>/dev/null || echo "FAILED")
if [ "$DNS_CACHE_RESPONSE" = "FAILED" ]; then
    fail "GET /policy/dns-cache is not responding"
else
    pass "GET /policy/dns-cache is responding"
fi

# Test the denied log GET endpoint.
DENIED_RESPONSE=$(curl -s --max-time 5 "$RYU_API/policy/denied-log" 2>/dev/null || echo "FAILED")
if [ "$DENIED_RESPONSE" = "FAILED" ]; then
    fail "GET /policy/denied-log is not responding"
else
    pass "GET /policy/denied-log is responding"
fi

# -- 5. OVS Flow Rules: Phase 2 Baseline --

section "OVS Flow Rules: Phase 2 Baseline (unchanged)"

FLOWS=$(ovs-ofctl dump-flows br0 2>/dev/null || echo "")

if [ -z "$FLOWS" ]; then
    fail "Could not dump OVS flows"
else
    if echo "$FLOWS" | grep -q "priority=1.*actions=drop"; then
        pass "Default deny rule is present (priority 1)"
    else
        fail "Default deny rule not found"
    fi

    if echo "$FLOWS" | grep -q "priority=200.*arp"; then
        pass "ARP rules are present (priority 200)"
    else
        fail "ARP rules not found"
    fi

    if echo "$FLOWS" | grep -q "priority=200.*udp.*tp_dst=67"; then
        pass "DHCP request rule is present"
    else
        fail "DHCP request rule not found"
    fi

    if echo "$FLOWS" | grep -q "priority=200.*tp_dst=53"; then
        pass "DNS query rule is present"
    else
        fail "DNS query rule not found"
    fi

    if echo "$FLOWS" | grep -q "priority=150.*nw_dst=192.168.50.0"; then
        pass "Anti-lateral-movement rule is present (priority 150)"
    else
        fail "Anti-lateral-movement rule not found"
    fi

    if echo "$FLOWS" | grep -q "priority=50.*ip"; then
        pass "General WAN access rules are present (priority 50)"
    else
        fail "General WAN access rules not found"
    fi
fi

# -- 6. Phase 3: Per-Device Intercept Rules (enforcing mode only) --

section "Phase 3: Per-Device Intercept Rules"

if [ "$ENF_MODE" = "enforcing" ]; then
    INTERCEPT_COUNT=$(echo "$FLOWS" | grep -c "priority=100" || echo "0")
    if [ "$INTERCEPT_COUNT" -gt 0 ]; then
        pass "Found $INTERCEPT_COUNT per-device intercept rule(s) at priority 100"
    else
        if [ "$PROFILED" -gt 0 ]; then
            fail "Enforcing mode is active with profiles, but no intercept rules at priority 100"
        else
            warn "Enforcing mode active but no profiles loaded (no intercept rules expected)"
        fi
    fi

    # Check for any reactive allowlist rules at priority 500.
    ALLOW_COUNT=$(echo "$FLOWS" | grep -c "priority=500" || echo "0")
    if [ "$ALLOW_COUNT" -gt 0 ]; then
        pass "Found $ALLOW_COUNT reactive allowlist rule(s) at priority 500"
    else
        warn "No reactive allowlist rules at priority 500 yet (normal if no traffic has flowed)"
    fi
else
    pass "In learning mode: per-device intercept rules are not expected"
    warn "Switch to enforcing mode when profiles are ready: curl -X POST -d '{\"mode\":\"enforcing\"}' http://127.0.0.1:8080/policy/allowlists/mode"
fi

# -- 7. Config File --

section "Phase 3: Configuration File"

# Check inside the container for the config file.
CONFIG_EXISTS=$(docker exec ryu-controller test -f /opt/ryu/config/device_profiles.json && echo "yes" || echo "no")
if [ "$CONFIG_EXISTS" = "yes" ]; then
    pass "device_profiles.json is present inside the Ryu container"
else
    warn "device_profiles.json not found inside the Ryu container at /opt/ryu/config/"
fi

# -- 8. DNS Cache Updater Service --

section "Phase 3: DNS Cache Updater"

if systemctl is-active --quiet dns-cache-updater 2>/dev/null; then
    pass "dns-cache-updater service is running"
elif [ -f /etc/systemd/system/dns-cache-updater.service ]; then
    warn "dns-cache-updater service file exists but is not running"
else
    warn "dns-cache-updater service is not installed yet (optional but recommended)"
fi

# -- 9. Connectivity Tests --

section "Connectivity: Essential Services (from gateway host)"

DNS_TEST=$(dig +short +time=3 @${BRIDGE_IP} google.com 2>/dev/null || echo "FAILED")
if [ "$DNS_TEST" != "FAILED" ] && [ -n "$DNS_TEST" ]; then
    pass "DNS resolution works through AdGuard"
else
    warn "DNS resolution test inconclusive from the host"
fi

echo ""
echo "  +---------------------------------------------------------+"
echo "  |  IMPORTANT: Test from an actual IoT / test device       |"
echo "  |                                                         |"
echo "  |  Connect a device to IoT-Security-AP and verify:        |"
echo "  |                                                         |"
echo "  |  1. Device gets DHCP lease (192.168.50.50-150)          |"
echo "  |  2. Device can resolve DNS: nslookup google.com         |"
echo "  |  3. Device can reach internet (if in learning mode)     |"
echo "  |                                                         |"
echo "  |  If in enforcing mode with a profile for the device:    |"
echo "  |                                                         |"
echo "  |  4. Device can reach its allowed destinations           |"
echo "  |  5. Device CANNOT reach un-allowed destinations         |"
echo "  |  6. Check denied log: curl $RYU_API/policy/denied-log   |"
echo "  +---------------------------------------------------------+"

# -- Summary --

echo ""
echo "============================================"
echo "  Phase 3 Verification Summary"
echo "============================================"
echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
echo "  WARN: $WARN"
echo "============================================"

if [ "$FAIL" -gt 0 ]; then
    echo "  Some checks FAILED. Review the output above."
    exit 1
else
    echo "  All critical checks passed."
    exit 0
fi
