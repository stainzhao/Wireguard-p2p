#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this uninstaller as root." >&2
    exit 1
fi

systemctl disable --now wireguard-p2p-client.service 2>/dev/null || true
rm -f /etc/systemd/system/wireguard-p2p-client.service
rm -f /etc/default/wireguard-p2p-client
rm -f /usr/local/bin/wireguard-p2p
rm -rf /run/wireguard-p2p-client
systemctl daemon-reload

echo "WireGuard P2P client removed. WireGuard itself was not modified."
