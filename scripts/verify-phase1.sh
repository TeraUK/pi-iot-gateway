#!/usr/bin/env bash
#
# verify-phase1.sh - Phase 1 Verification
#
# Tests that POL-03 (DNS filtering) and POL-09 (logging) are working
# correctly after applying the Phase 1 configuration changes.
#
# Run from the gateway host (not from inside a container).
#
# Usage: sudo ./verify-phase1.sh

set -euo pipefail

BRIDGE_IP="192.168.50.1"
ADGUARD_CONTAINER_IP="172.20.0.53"
PASS=0
FAIL=0
WARN=0

pass() { echo "  [PASS] $1"; PASS=$((PASS + 1)); }
fail() { echo "  [FAIL] $1"; FAIL=$((FAIL + 1)); }
warn() { echo "  [WARN] $1"; WARN=$((WARN + 1)); }
section() { echo ""; echo "== $1 =="; }

# ── 1. AdGuard Home Status ────────────────────────────────────

section "POL-03: AdGuard Home Container"

AG_STATE=$(docker inspect --format '{{.State.Status}}' adguard-home 2>/dev/null || echo "not found")
if [ "$AG_STATE" = "running" ]; then
    pass "AdGuard Home container is running"
else
    fail "AdGuard Home container is not running (state: $AG_STATE)"
fi

AG_IP=$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' adguard-home 2>/dev/null || echo "unknown")
if [ "$AG_IP" = "$ADGUARD_CONTAINER_IP" ]; then
    pass "AdGuard container IP is $AG_IP (matches DNAT target)"
else
    fail "AdGuard container IP is $AG_IP (expected $ADGUARD_CONTAINER_IP)"
fi

# ── 2. DNSSEC Enabled ────────────────────────────────────────

section "POL-03: DNSSEC Validation"

# Check the config file for DNSSEC setting.
DNSSEC_ENABLED=$(docker exec adguard-home cat /opt/adguardhome/conf/AdGuardHome.yaml 2>/dev/null | grep "enable_dnssec" | head -1 || echo "")
if echo "$DNSSEC_ENABLED" | grep -q "true"; then
    pass "DNSSEC is enabled in AdGuard config"
else
    fail "DNSSEC is not enabled in AdGuard config"
fi

# ── 3. Blocklist Count ────────────────────────────────────────

section "POL-03: DNS Blocklists"

FILTER_COUNT=$(docker exec adguard-home cat /opt/adguardhome/conf/AdGuardHome.yaml 2>/dev/null | grep -c "enabled: true" | head -1 || echo "0")
# Rough check: we expect at least 7 enabled filters.
FILTER_URLS=$(docker exec adguard-home cat /opt/adguardhome/conf/AdGuardHome.yaml 2>/dev/null | grep "url:" | wc -l || echo "0")
if [ "$FILTER_URLS" -ge 7 ]; then
    pass "Found $FILTER_URLS blocklist URLs configured (expected >= 7)"
else
    warn "Found $FILTER_URLS blocklist URLs (expected >= 7). Check if IoT-specific lists were added."
fi

# ── 4. DNS Resolution Works ──────────────────────────────────

section "POL-03: DNS Resolution (Legitimate Queries)"

# Test that a known-good domain resolves through AdGuard.
RESOLVE_TEST=$(dig +short +time=5 @${BRIDGE_IP} google.com 2>/dev/null || echo "FAILED")
if [ "$RESOLVE_TEST" != "FAILED" ] && [ -n "$RESOLVE_TEST" ]; then
    pass "google.com resolves via AdGuard (${BRIDGE_IP}:53)"
else
    fail "google.com failed to resolve via AdGuard"
fi

# ── 5. DNS Blocking Works ────────────────────────────────────

section "POL-03: DNS Blocking (Malicious/Ad Domains)"

# Test that a known ad/tracking domain is blocked.
# doubleclick.net should be blocked by most ad blocklists.
BLOCK_TEST=$(dig +short +time=5 @${BRIDGE_IP} doubleclick.net 2>/dev/null || echo "FAILED")
if [ "$BLOCK_TEST" = "0.0.0.0" ] || [ "$BLOCK_TEST" = "127.0.0.1" ] || [ -z "$BLOCK_TEST" ]; then
    pass "doubleclick.net is blocked by AdGuard"
else
    warn "doubleclick.net resolved to $BLOCK_TEST (may not be blocked yet - check blocklist sync)"
fi

# Test a known malware domain from threat intelligence feeds.
MALWARE_TEST=$(dig +short +time=5 @${BRIDGE_IP} malware.testcategory.com 2>/dev/null || echo "FAILED")
# This domain may or may not exist in blocklists. Just informational.
echo "  [INFO] malware.testcategory.com result: ${MALWARE_TEST:-NXDOMAIN}"

# ── 6. nftables DNS Interception ──────────────────────────────

section "POL-03: nftables DNS Interception"

NFT_RULESET=$(nft list ruleset 2>/dev/null || echo "")

if echo "$NFT_RULESET" | grep -q "dnat to $ADGUARD_CONTAINER_IP"; then
    pass "DNS DNAT rule is active (redirects port 53 to AdGuard)"
else
    fail "DNS DNAT rule not found. Devices with hardcoded DNS can bypass AdGuard."
fi

# ── 7. DoT Blocking ──────────────────────────────────────────

section "POL-03: DNS-over-TLS Blocking"

if echo "$NFT_RULESET" | grep -q "tcp dport 853"; then
    pass "DoT blocking rule (port 853) is active"
else
    fail "DoT blocking rule not found. Devices can bypass AdGuard via DNS-over-TLS."
fi

if echo "$NFT_RULESET" | grep -q "udp dport 8853"; then
    pass "DoQ blocking rule (port 8853) is active"
else
    warn "DoQ blocking rule not found (optional, few devices use DNS-over-QUIC)"
fi

# ── 8. Zeek Logging ──────────────────────────────────────────

section "POL-09: Zeek Log Generation"

ZEEK_STATE=$(docker inspect --format '{{.State.Status}}' zeek 2>/dev/null || echo "not found")
if [ "$ZEEK_STATE" = "running" ]; then
    pass "Zeek container is running"
else
    fail "Zeek container is not running (state: $ZEEK_STATE)"
fi

# Check for log files in the Zeek volume.
ZEEK_LOGS=$(docker exec zeek ls /opt/zeek-logs/ 2>/dev/null || echo "")
if echo "$ZEEK_LOGS" | grep -q "conn"; then
    pass "Zeek is generating connection logs"
else
    warn "No conn.log found yet (may need traffic to generate)"
fi

if echo "$ZEEK_LOGS" | grep -q "dns"; then
    pass "Zeek is generating DNS logs"
else
    warn "No dns.log found yet (may need DNS traffic to generate)"
fi

# Check if JSON logging is enabled.
ZEEK_LOG_CONTENT=$(docker exec zeek head -1 /opt/zeek-logs/conn.log 2>/dev/null || echo "")
if echo "$ZEEK_LOG_CONTENT" | grep -q "{"; then
    pass "Zeek is using JSON log format"
else
    warn "Zeek may not be using JSON format (check local.zeek config)"
fi

# ── 9. Mirror Port ───────────────────────────────────────────

section "POL-09: OVS Mirror (Zeek Traffic Feed)"

if ip link show zeek-veth-h &>/dev/null; then
    pass "Host-side veth (zeek-veth-h) exists"
else
    fail "Host-side veth (zeek-veth-h) not found"
fi

MIRROR_EXISTS=$(ovs-vsctl list mirror 2>/dev/null | grep -c "zeek-mirror" || echo "0")
if [ "$MIRROR_EXISTS" -gt 0 ]; then
    pass "OVS mirror 'zeek-mirror' is configured"
else
    fail "OVS mirror not configured. Zeek cannot see traffic."
fi

# ── 10. AdGuard Query Logging ─────────────────────────────────

section "POL-09: AdGuard Query Logging"

QUERYLOG_ENABLED=$(docker exec adguard-home cat /opt/adguardhome/conf/AdGuardHome.yaml 2>/dev/null | grep -A8 "querylog:" | grep "enabled:" | head -1 || echo "")
if echo "$QUERYLOG_ENABLED" | grep -q "true"; then
    pass "AdGuard query logging is enabled"
else
    fail "AdGuard query logging is not enabled"
fi

QUERYLOG_INTERVAL=$(docker exec adguard-home cat /opt/adguardhome/conf/AdGuardHome.yaml 2>/dev/null | grep -A8 "querylog:" | grep "interval:" | head -1 || echo "")
if echo "$QUERYLOG_INTERVAL" | grep -q "2160h"; then
    pass "AdGuard query log retention is 2160h (90 days)"
else
    warn "AdGuard query log retention: $QUERYLOG_INTERVAL (expected 2160h)"
fi

# ── 11. dnsmasq DHCP Logging ──────────────────────────────────

section "POL-09: dnsmasq DHCP Logging"

if [ -f "/var/lib/misc/dnsmasq.leases" ]; then
    LEASE_COUNT=$(wc -l < /var/lib/misc/dnsmasq.leases)
    pass "dnsmasq lease file exists (${LEASE_COUNT} leases)"
else
    warn "dnsmasq lease file not found (no clients have connected yet?)"
fi

DNSMASQ_LOG=$(grep -c "dnsmasq" /var/log/syslog 2>/dev/null || echo "0")
if [ "$DNSMASQ_LOG" -gt 0 ]; then
    pass "dnsmasq DHCP events are being logged to syslog"
else
    warn "No dnsmasq entries found in syslog"
fi

# ── 12. Log Maintenance Cron ──────────────────────────────────

section "POL-09: Log Maintenance"

if crontab -l 2>/dev/null | grep -q "log-maintenance"; then
    pass "Log maintenance cron job is installed"
else
    warn "Log maintenance cron job not found. Install with: sudo crontab -e"
fi

# ── Summary ───────────────────────────────────────────────────

echo ""
echo "============================================"
echo "  Phase 1 Verification Summary"
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

