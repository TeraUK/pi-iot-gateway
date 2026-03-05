#!/usr/bin/env bash
#
# attach-zeek-mirror.sh
#
# Creates a veth pair and attaches one end to the Zeek container for
# OVS traffic mirroring. Run this AFTER docker compose up.
# Must be copied to /usr/local/bin
# Usage: sudo /usr/local/bin/attach-zeek-mirror.sh
#

set -euo pipefail

CONTAINER_NAME="zeek"
# Host-side veth end (added to OVS as a port)
VETH_HOST="zeek-veth-h"
# Container-side veth end (Zeek sniffs on this)
VETH_CONTAINER="zeek-eth1"

echo "=== Zeek Mirror Port Attachment ==="

# --- Step 1: Get the Zeek container's PID ---
ZEEK_PID=$(docker inspect --format '{{.State.Pid}}' "$CONTAINER_NAME" 2>/dev/null)
if [ -z "$ZEEK_PID" ] || [ "$ZEEK_PID" = "0" ]; then
    echo "ERROR: Container '$CONTAINER_NAME' is not running."
    exit 1
fi
echo "Zeek container PID: $ZEEK_PID"

# --- Step 2: Create a symlink for the container's network namespace ---
# Docker does not create /var/run/netns/ entries by default.
# We create one so 'ip netns exec' can access the container's namespace.
sudo mkdir -p /var/run/netns
sudo ln -sf "/proc/$ZEEK_PID/ns/net" "/var/run/netns/$CONTAINER_NAME"
echo "Network namespace symlink created."

# --- Step 3: Clean up any stale veth pair or OVS port ---
if ip link show "$VETH_HOST" &>/dev/null; then
    echo "Cleaning up stale veth pair..."
    sudo ovs-vsctl --if-exists del-port br0 "$VETH_HOST"
    sudo ip link delete "$VETH_HOST" 2>/dev/null || true
fi

# --- Step 4: Create the veth pair ---
sudo ip link add "$VETH_HOST" type veth peer name "$VETH_CONTAINER"
echo "veth pair created: $VETH_HOST <-> $VETH_CONTAINER"

# --- Step 5: Move the container-side end into the Zeek namespace ---
sudo ip link set "$VETH_CONTAINER" netns "$CONTAINER_NAME"
echo "$VETH_CONTAINER moved into Zeek's network namespace."

# --- Step 6: Bring up both ends ---
sudo ip link set "$VETH_HOST" up
sudo ip netns exec "$CONTAINER_NAME" ip link set "$VETH_CONTAINER" up

# Set the interface to promiscuous mode inside the container so Zeek
# can capture all mirrored traffic.
sudo ip netns exec "$CONTAINER_NAME" ip link set "$VETH_CONTAINER" promisc on
echo "Both veth ends are up."

# --- Step 7: Add the host-side end to OVS ---
sudo ovs-vsctl --may-exist add-port br0 "$VETH_HOST"
echo "$VETH_HOST added to OVS bridge br0."

# --- Step 8: Configure OVS mirroring ---
# Remove any existing mirror first.
sudo ovs-vsctl --if-exists -- --id=@m get mirror zeek-mirror -- remove bridge br0 mirrors @m 2>/dev/null || true

# Create the mirror: copy ALL bridge traffic to the Zeek veth port.
sudo ovs-vsctl \
    -- --id=@p get port "$VETH_HOST" \
    -- --id=@m create mirror name=zeek-mirror select-all=true output-port=@p \
    -- set bridge br0 mirrors=@m
echo "OVS mirror 'zeek-mirror' configured — all traffic mirrored to Zeek."

echo ""
echo "=== Done. Zeek should now be receiving mirrored traffic on $VETH_CONTAINER ==="
echo "If Zeek was restarting waiting for the interface, it should stabilise now."
