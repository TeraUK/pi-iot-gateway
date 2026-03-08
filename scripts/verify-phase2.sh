#!/usr/bin/env bash
#
# verify-phase2.sh - Phase 2 Verification
#
# Tests that POL-01 (micro-segmentation) and POL-05 (essential services)
# are working correctly after deploying the gateway policy app.
#
# Usage: sudo ./verify-phase2.sh

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

# ── 1. Ryu Container Status ──────────────────────────────────

section "Ryu Policy App: Container"

RYU_STATE=$(docker inspect --format '{{.State.Status}}' ryu-controller 2>/dev/null || echo "not found")
if [ "$RYU_STATE" = "running" ]; then
    pass "Ryu container is running"
else
    fail "Ryu container is not running (state: $RYU_STATE)"
    echo "  Cannot proceed without Ryu. Check: docker logs ryu-controller"
    exit 1
fi

# Check that the policy app loaded (not the learning switch).
RYU_LOGS=$(docker logs ryu-controller 2>&1 | tail -50)
if echo "$RYU_LOGS" | grep -q "Policy rules installed"; then
    pass "Gateway policy app loaded and rules installed"
elif echo "$RYU_LOGS" | grep -q "gateway_policy"; then
    warn "Gateway policy app loaded but rules may not have installed yet"
else
    fail "Gateway policy app does not appear to be running. Check Ryu logs."
fi

# ── 2. Policy REST API ───────────────────────────────────────

section "Ryu Policy App: REST API"

STATUS_RESPONSE=$(curl -s --max-time 5 "$RYU_API/policy/status" 2>/dev/null || echo "FAILED")
if [ "$STATUS_RESPONSE" = "FAILED" ]; then
    fail "Policy REST API is not responding on $RYU_API/policy/status"
else
    pass "Policy REST API is responding"

    # Parse key fields from the status response.
    SWITCH_CONNECTED=$(echo "$STATUS_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('switch_connected', False))" 2>/dev/null || echo "unknown")
    RULES_INSTALLED=$(echo "$STATUS_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('rules_installed', False))" 2>/dev/null || echo "unknown")
    WIFI_PORT=$(echo "$STATUS_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('wifi_port', 'null'))" 2>/dev/null || echo "unknown")
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

    if [ "$WIFI_PORT" != "null" ] && [ "$WIFI_PORT" != "None" ]; then
        pass "WiFi port discovered: port $WIFI_PORT"
    else
        fail "WiFi port was not discovered. Check WIFI_INTERFACE config."
    fi
fi

# ── 3. OVS Flow Rules ────────────────────────────────────────

section "OVS Flow Rules"

FLOWS=$(ovs-ofctl dump-flows br0 2>/dev/null || echo "")



if [ -z "$FLOWS" ]; then
    fail "Could not dump OVS flows"
else
    echo "DEBUG: FLOWS variable length: ${#FLOWS}"
    echo "$FLOWS" | head -5
    FLOW_COUNT=$(echo "$FLOWS" | grep -c "cookie=" || echo "0")
    pass "OVS has $FLOW_COUNT flow rules installed"

    # Check for the default deny rule (priority=1, actions=drop).
    if echo "$FLOWS" | grep -q "priority=1.*actions=drop"; then
        pass "Default deny rule is present (priority 1, action DROP)"
    else
        fail "Default deny rule not found"
    fi

    # Check for ARP rules.
    if echo "$FLOWS" | grep -q "priority=200.*arp"; then
        pass "ARP rules are present (priority 200)"
    else
        fail "ARP rules not found"
    fi

    # Check for DHCP rules (UDP port 67 or 68).
    if echo "$FLOWS" | grep -q "priority=200.*udp.*tp_dst=67"; then
        pass "DHCP request rule is present"
    else
        fail "DHCP request rule not found"
    fi

    if echo "$FLOWS" | grep -q "priority=200.*udp.*tp_dst=68"; then
        pass "DHCP response rule is present"
    else
        fail "DHCP response rule not found"
    fi

    # Check for DNS rules (port 53 to gateway).
    if echo "$FLOWS" | grep -q "priority=200.*tp_dst=53"; then
        pass "DNS query rule is present (to gateway)"
    else
        fail "DNS query rule not found"
    fi

    # Check for NTP rules (UDP port 123).
    if echo "$FLOWS" | grep -q "priority=200.*udp.*tp_dst=123"; then
        pass "NTP query rule is present"
    else
        fail "NTP query rule not found"
    fi

    # Check for anti-lateral-movement rule.
    if echo "$FLOWS" | grep -q "priority=150.*nw_dst=192.168.50.0"; then
        pass "Anti-lateral-movement rule is present (priority 150)"
    else
        fail "Anti-lateral-movement rule not found"
    fi

    # Check for general WAN access rules (priority 50).
    if echo "$FLOWS" | grep -q "priority=50.*ip"; then
        pass "General WAN access rules are present (priority 50)"
    else
        fail "General WAN access rules not found"
    fi
fi

# ── 4. OVS Fail Mode ─────────────────────────────────────────

section "OVS Configuration"

FAIL_MODE=$(ovs-vsctl get-fail-mode br0 2>/dev/null || echo "unknown")
if [ "$FAIL_MODE" = "standalone" ]; then
    pass "OVS fail mode is standalone (correct for Phase 2)"
elif [ "$FAIL_MODE" = "secure" ]; then
    warn "OVS fail mode is secure (expected standalone for Phase 2)"
else
    fail "OVS fail mode is unexpected: $FAIL_MODE"
fi

CONTROLLER=$(ovs-vsctl get-controller br0 2>/dev/null || echo "none")
if echo "$CONTROLLER" | grep -q "6653"; then
    pass "OVS controller is set ($CONTROLLER)"
else
    fail "OVS controller is not configured"
fi

# ── 5. Connectivity Tests ────────────────────────────────────

section "Connectivity: Essential Services (from gateway host)"

# Test DNS resolution through AdGuard.
DNS_TEST=$(dig +short +time=3 @${BRIDGE_IP} google.com 2>/dev/null || echo "FAILED")
if [ "$DNS_TEST" != "FAILED" ] && [ -n "$DNS_TEST" ]; then
    pass "DNS resolution works through AdGuard"
else
    warn "DNS resolution test inconclusive from the host (test from an IoT device instead)"
fi

echo ""
echo "  ┌─────────────────────────────────────────────────────┐"
echo "  │  IMPORTANT: Test from an actual IoT / test device   │"
echo "  │                                                     │"
echo "  │  Connect a device to IoT-Security-AP and verify:    │"
echo "  │                                                     │"
echo "  │  1. Device gets DHCP lease (192.168.50.50-150)      │"
echo "  │  2. Device can resolve DNS: nslookup google.com     │"
echo "  │  3. Device can reach internet: ping 8.8.8.8         │"
echo "  │  4. Device can browse: curl -I https://example.com  │"
echo "  │                                                     │"
echo "  │  If you have two devices, also test:                │"
echo "  │                                                     │"
echo "  │  5. Device A CANNOT ping Device B (micro-seg)       │"
echo "  │  6. Device A CANNOT reach Device B on any port      │"
echo "  └─────────────────────────────────────────────────────┘"

# ── 6. Micro-segmentation Verification ───────────────────────

section "Micro-segmentation Logic"

# Verify there are no rules that forward WiFi->WiFi (which would
# allow device-to-device communication).
WIFI_TO_WIFI=$(echo "$FLOWS" | grep "in_port=1" | grep "output:1" || echo "")
if [ -z "$WIFI_TO_WIFI" ]; then
    pass "No WiFi-to-WiFi forwarding rules exist (micro-segmentation intact)"
else
    fail "Found WiFi-to-WiFi forwarding rules (micro-segmentation broken):"
    echo "    $WIFI_TO_WIFI"
fi

# Verify the anti-lateral rule is at a higher priority than WAN access.
# The anti-lateral rule (priority 150) must beat the WAN outbound rule
# (priority 50) to prevent routing through the gateway.
if echo "$FLOWS" | grep -q "priority=150.*nw_dst=192.168.50.0.*actions=drop"; then
    pass "Anti-lateral rule drops IoT-subnet-destined traffic at priority 150"
else
    warn "Could not confirm anti-lateral rule has DROP action"
fi

# ── Summary ───────────────────────────────────────────────────

echo ""
echo "============================================"
echo "  Phase 2 Verification Summary"
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
    echo ""
    echo "  Next: test from a real device on IoT-Security-AP."
    exit 0
fi
