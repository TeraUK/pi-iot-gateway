#!/bin/bash
#
# Waits for the mirror interface (zeek-eth1) to be attached by the
# host-side attach-zeek-mirror.sh script, then starts Zeek.
# This keeps the container alive and avoids a crash loop.
#
# The container never exits while waiting. Exiting would trigger a
# restart, which creates a new network namespace and invalidates any
# veth pair the host-side script may have already attached to the
# previous namespace. Staying alive keeps the namespace stable.
#
# Requires execute permissions: chmod +x ~/iot-gateway/zeek/entrypoint.sh

IFACE="zeek-eth1"
WARN_INTERVAL=60
ELAPSED=0

echo "Waiting for interface $IFACE to appear..."

while [ ! -d "/sys/class/net/$IFACE" ]; do
    sleep 2
    ELAPSED=$((ELAPSED + 2))
    if [ "$((ELAPSED % WARN_INTERVAL))" -eq 0 ]; then
        echo "WARNING: $IFACE has not appeared after ${ELAPSED}s. Is attach-zeek-mirror.sh running on the host?"
    fi
done

echo "$IFACE is up. Starting Zeek."
exec zeek -i "$IFACE" -C /usr/local/zeek/share/zeek/site/local.zeek
