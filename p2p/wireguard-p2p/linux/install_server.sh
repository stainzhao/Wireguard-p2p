#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || { echo "Run as root." >&2; exit 1; }
[ "$#" -ge 2 ] || { echo "Usage: sudo ./install_server.sh <service-user> <overlay-ip> [wg-interface]" >&2; exit 2; }
SERVICE_USER=$1
OVERLAY_IP=$2
WG_INTERFACE=${3:-wg0}
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MANAGER_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../manage" && pwd)
TARGET=/opt/wireguard-p2p

install -d -m 0755 "$TARGET"
for f in p2p_agent.py candidates.py portmap.py portmap_daemon.py; do install -m 0644 "$SCRIPT_DIR/$f" "$TARGET/$f"; done
sed -e "s/__SERVICE_USER__/$SERVICE_USER/g" -e "s/__OVERLAY_IP__/$OVERLAY_IP/g" "$SCRIPT_DIR/wireguard-p2p-agent.service" > /etc/systemd/system/wireguard-p2p-agent.service
sed -e "s/__SERVICE_USER__/$SERVICE_USER/g" -e "s/Environment=P2P_INTERFACE=wg0/Environment=P2P_INTERFACE=$WG_INTERFACE/" "$SCRIPT_DIR/wireguard-p2p-portmap.service" > /etc/systemd/system/wireguard-p2p-portmap.service
install -m 0755 "$MANAGER_DIR/wireguard-p2p.py" /usr/local/bin/wireguard-p2p
systemctl daemon-reload
systemctl enable wireguard-p2p-agent.service wireguard-p2p-portmap.service
systemctl restart wireguard-p2p-portmap.service
systemctl restart wireguard-p2p-agent.service
printf 'Installed managed server. Future updates: sudo wireguard-p2p update\n'
