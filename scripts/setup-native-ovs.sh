#!/usr/bin/env bash
#
# setup-native-ovs.sh
#
# Configures Open vSwitch for the IoT Security Gateway.
# Run this once during initial setup, or to recreate the OVS
# configuration on a fresh deployment.
# Must be copied to /usr/local/bin
# Usage: sudo /usr/local/bin/setup-native-ovs.sh
# Ensure script has execute permisions: sudo chmod +x /usr/local/bin/setup-ovs.sh
#
# Prerequisites:
#   - Open vSwitch is installed (apt install openvswitch-switch)
#   - The WiFi interface (WIFI_IFACE) exists and is not managed by
#     NetworkManager or wpa_supplicant
#

set -euo pipefail

# ── Configuration ──────────────────────────────────────────────
# Edit these variables to match your environment.

BRIDGE="br0"
WIFI_IFACE="wlp3s0"
BRIDGE_IP="192.168.50.1/24"

# OVS fail mode: "standalone" for development (traffic flows even if
# the controller is down), "secure" for production (traffic is dropped
# if the controller is unreachable).
FAIL_MODE="standalone"

# Ryu controller address. Leave empty to skip controller configuration.
# Set this once Ryu is deployed and you are ready to connect.
CONTROLLER="tcp:127.0.0.1:6653"

# ── Preflight Checks ──────────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script must be run as root (sudo)."
    exit 1
fi

if ! command -v ovs-vsctl &>/dev/null; then
    echo "ERROR: ovs-vsctl not found. Install Open vSwitch first:"
    echo "  sudo apt install openvswitch-switch"
    exit 1
fi

if ! systemctl is-active --quiet ovs-vswitchd; then
    echo "Starting Open vSwitch..."
    systemctl start ovs-vswitchd
fi

if ! ip link show "$WIFI_IFACE" &>/dev/null; then
    echo "ERROR: Interface $WIFI_IFACE does not exist."
    echo "Check the WIFI_IFACE variable at the top of this script."
    exit 1
fi

# ── Bridge Setup ──────────────────────────────────────────────

echo "=== OVS Bridge Setup ==="

# Create the bridge (idempotent — safe to re-run)
if ovs-vsctl br-exists "$BRIDGE"; then
    echo "Bridge $BRIDGE already exists."
else
    ovs-vsctl add-br "$BRIDGE"
    echo "Bridge $BRIDGE created."
fi

# Add the WiFi interface as a port
ovs-vsctl --may-exist add-port "$BRIDGE" "$WIFI_IFACE"
echo "Port $WIFI_IFACE added to $BRIDGE."

# ── Bridge IP ─────────────────────────────────────────────────
# Assign the gateway IP to the bridge's internal port.
# This is also handled persistently by systemd-networkd via
# 50-br0.network, but we set it here so the bridge is usable
# immediately without waiting for networkd to pick it up.

if ! ip addr show "$BRIDGE" | grep -q "${BRIDGE_IP%/*}"; then
    ip addr add "$BRIDGE_IP" dev "$BRIDGE"
    echo "Assigned $BRIDGE_IP to $BRIDGE."
else
    echo "$BRIDGE already has $BRIDGE_IP."
fi

ip link set "$BRIDGE" up
ip link set "$WIFI_IFACE" up
echo "Interfaces are up."

# ── Fail Mode ─────────────────────────────────────────────────

ovs-vsctl set-fail-mode "$BRIDGE" "$FAIL_MODE"
echo "Fail mode set to: $FAIL_MODE"

# ── Controller ────────────────────────────────────────────────

if [ -n "$CONTROLLER" ]; then
    ovs-vsctl set-controller "$BRIDGE" "$CONTROLLER"
    echo "Controller set to: $CONTROLLER"
else
    ovs-vsctl del-controller "$BRIDGE" 2>/dev/null || true
    echo "No controller configured (standalone switching only)."
fi

# ── Verify ────────────────────────────────────────────────────

echo ""
echo "=== OVS Configuration ==="
ovs-vsctl show
echo ""
echo "=== Bridge $BRIDGE ==="
echo "Fail mode:  $(ovs-vsctl get-fail-mode "$BRIDGE")"
echo "Controller: $(ovs-vsctl get-controller "$BRIDGE" 2>/dev/null || echo 'none')"
echo "Ports:      $(ovs-vsctl list-ports "$BRIDGE" | tr '\n' ' ')"
echo "IP address: $(ip -4 addr show "$BRIDGE" | grep inet | awk '{print $2}')"
echo ""
echo "=== Done ==="
