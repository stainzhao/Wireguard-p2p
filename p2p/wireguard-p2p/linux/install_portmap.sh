#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this installer as root." >&2
    exit 1
fi

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TARGET_DIR=/opt/wireguard-p2p
UNIT=/etc/systemd/system/wireguard-p2p-portmap.service

SERVICE_USER=$(systemctl show wireguard-p2p-agent.service -p User --value 2>/dev/null || true)
if [ -z "$SERVICE_USER" ]; then
    SERVICE_USER=${1:-}
fi
if [ -z "$SERVICE_USER" ]; then
    echo "Unable to determine the Agent service user. Pass it as argument 1." >&2
    exit 1
fi

install -d -m 0755 "$TARGET_DIR"
install -m 0644 "$SCRIPT_DIR/portmap.py" "$TARGET_DIR/portmap.py"
install -m 0644 "$SCRIPT_DIR/portmap_daemon.py" "$TARGET_DIR/portmap_daemon.py"
install -m 0644 "$SCRIPT_DIR/candidates.py" "$TARGET_DIR/candidates.py"

sed "s/__SERVICE_USER__/$SERVICE_USER/g" \
    "$SCRIPT_DIR/wireguard-p2p-portmap.service" > "$UNIT"
chmod 0644 "$UNIT"

systemctl daemon-reload
systemctl enable --now wireguard-p2p-portmap.service
# Reload the candidate module in the already-running Agent.
systemctl restart wireguard-p2p-agent.service

systemctl --no-pager --full status wireguard-p2p-portmap.service || true

echo
echo "Current mapped4 cache:"
cat /var/lib/wireguard-p2p/mapped4.json 2>/dev/null || echo "No mapping yet (router may not support PCP/NAT-PMP/UPnP)."
