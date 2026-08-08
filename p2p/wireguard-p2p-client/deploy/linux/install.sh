#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this installer as root." >&2
    exit 1
fi

INTERFACE=wg0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --interface)
            [ "$#" -ge 2 ] || { echo "--interface requires a value" >&2; exit 2; }
            INTERFACE=$2
            shift 2
            ;;
        -h|--help)
            echo "Usage: sudo ./install.sh [--interface wg0]"
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

command -v systemctl >/dev/null 2>&1 || { echo "systemd is required." >&2; exit 1; }
command -v wg >/dev/null 2>&1 || { echo "wireguard-tools is required (wg not found)." >&2; exit 1; }

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BINARY="$SCRIPT_DIR/wireguard-p2p"
UNIT_SOURCE="$SCRIPT_DIR/wireguard-p2p-client.service"

[ -x "$BINARY" ] || { echo "Missing executable: $BINARY" >&2; exit 1; }
[ -f "$UNIT_SOURCE" ] || { echo "Missing systemd unit: $UNIT_SOURCE" >&2; exit 1; }

install -m 0755 "$BINARY" /usr/local/bin/wireguard-p2p
install -m 0644 "$UNIT_SOURCE" /etc/systemd/system/wireguard-p2p-client.service
install -d -m 0755 /etc/default
printf 'P2P_INTERFACE=%s\n' "$INTERFACE" > /etc/default/wireguard-p2p-client
chmod 0644 /etc/default/wireguard-p2p-client

if ! wg show "$INTERFACE" >/dev/null 2>&1; then
    echo "Warning: WireGuard interface '$INTERFACE' is not active yet."
    echo "The client will keep restarting until the interface becomes available."
fi

systemctl daemon-reload
systemctl enable wireguard-p2p-client.service
systemctl restart wireguard-p2p-client.service
sleep 1
systemctl --no-pager --full status wireguard-p2p-client.service || true

echo
echo "Installed WireGuard P2P client for interface: $INTERFACE"
echo "The existing WireGuard configuration and AllowedIPs were not modified."
