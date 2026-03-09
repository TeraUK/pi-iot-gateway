#!/usr/bin/env bash
#
# attach-zeek-mirror.sh
#
# Creates a veth pair and attaches one end to the Zeek container for OVS traffic mirroring.
# Must be copied to /usr/local/bin
# Usage: sudo /usr/local/bin/attach-zeek-mirror.sh
#
# Watches for the Zeek container to start and attaches an OVS mirror
# port each time. Runs as a long-lived service so that container
# restarts, reboots, and docker compose up/down cycles are allhandled automatically.

set -uo pipefail

CONTAINER_NAME="zeek"
VETH_HOST="zeek-veth-h"
VETH_CONTAINER="zeek-eth1"

attach_mirror() {
    echo "=== Attaching mirror port to Zeek ==="

    # Get the Zeek container's PID
    ZEEK_PID=$(docker inspect --format '{{.State.Pid}}' "$CONTAINER_NAME" 2>/dev/null)
    if [ -z "$ZEEK_PID" ] || [ "$ZEEK_PID" = "0" ]; then
        echo "ERROR: Container '$CONTAINER_NAME' is not running."
        return 1
    fi
    echo "Zeek container PID: $ZEEK_PID"

    # Create a symlink for the container's network namespace
    mkdir -p /var/run/netns
    ln -sf "/proc/$ZEEK_PID/ns/net" "/var/run/netns/$CONTAINER_NAME"

    # Clean up any stale veth pair or OVS port
    if ip link show "$VETH_HOST" &>/dev/null; then
        echo "Cleaning up stale veth pair..."
        ovs-vsctl --if-exists del-port br0 "$VETH_HOST"
        ip link delete "$VETH_HOST" 2>/dev/null || true
    fi

    # Create the veth pair
    ip link add "$VETH_HOST" type veth peer name "$VETH_CONTAINER"
    echo "veth pair created: $VETH_HOST <-> $VETH_CONTAINER"

    # Move the container-side end into the Zeek namespace
    ip link set "$VETH_CONTAINER" netns "$CONTAINER_NAME"
    echo "$VETH_CONTAINER moved into Zeek's network namespace."

    # Bring up both ends
    ip link set "$VETH_HOST" up
    ip netns exec "$CONTAINER_NAME" ip link set "$VETH_CONTAINER" up
    ip netns exec "$CONTAINER_NAME" ip link set "$VETH_CONTAINER" promisc on
    echo "Both veth ends are up."

    # Add the host-side end to OVS
    ovs-vsctl --may-exist add-port br0 "$VETH_HOST"
    echo "$VETH_HOST added to OVS bridge br0."

    # Configure OVS mirroring
    ovs-vsctl -- --id=@m get mirror zeek-mirror -- remove bridge br0 mirrors @m 2>/dev/null || true
    ovs-vsctl \
        -- --id=@p get port "$VETH_HOST" \
        -- --id=@m create mirror name=zeek-mirror select-all=true output-port=@p \
        -- set bridge br0 mirrors=@m
    echo "OVS mirror 'zeek-mirror' configured."
    echo "=== Done ==="
}

cleanup() {
    echo "Cleaning up..."
    rm -f /var/run/netns/zeek # Remove the symlink to the container's network namespace
    ovs-vsctl --if-exists del-port br0 "$VETH_HOST"
    ip link delete "$VETH_HOST" 2>/dev/null || true
    exit 0
}

trap cleanup SIGTERM SIGINT

echo "Zeek mirror watcher starting. Waiting for container events..."

# Attach immediately if Zeek is already running
if docker inspect --format '{{.State.Running}}' "$CONTAINER_NAME" 2>/dev/null | grep -q true; then
    echo "Zeek is already running. Attaching now."
    attach_mirror
fi

# Watch for Zeek container start events and re-attach each time.
# This loop runs forever. When Zeek restarts (new namespace), the
# start event fires and we re-attach the mirror port automatically.
docker events --filter "container=$CONTAINER_NAME" --filter "event=start" --format '{{.Status}}' | while read -r event; do
    echo "Detected Zeek container start event."
    # Brief pause to let the container fully initialise
    sleep 2
    attach_mirror
done
