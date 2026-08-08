#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || { echo "Run as root." >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required." >&2; exit 1; }
command -v systemctl >/dev/null 2>&1 || { echo "systemd is required." >&2; exit 1; }
command -v wg >/dev/null 2>&1 || { echo "wireguard-tools is required." >&2; exit 1; }
command -v ip >/dev/null 2>&1 || { echo "iproute2 is required." >&2; exit 1; }
command -v useradd >/dev/null 2>&1 || { echo "useradd is required." >&2; exit 1; }

WG_INTERFACE=wg0
if [ "${1:-}" = "--interface" ]; then
    [ "$#" -ge 2 ] || { echo "--interface requires a value" >&2; exit 2; }
    WG_INTERFACE=$2
elif [ "$#" -ge 1 ]; then
    WG_INTERFACE=$1
fi
wg show "$WG_INTERFACE" >/dev/null 2>&1 || { echo "WireGuard interface '$WG_INTERFACE' is not active." >&2; exit 1; }

OVERLAY_IP=$(ip -4 -o addr show dev "$WG_INTERFACE" | awk '$4 ~ /^10\.0\.0\./ {sub(/\/.*/, "", $4); print $4; exit}')
case "$OVERLAY_IP" in
    10.0.0.0|10.0.0.1|10.0.0.255|"") echo "Overlay IP '${OVERLAY_IP:-none}' cannot be used as a P2P server." >&2; exit 1 ;;
    10.0.0.*) ;;
    *) echo "P2P server requires an eligible 10.0.0.x overlay address; detected '${OVERLAY_IP:-none}'." >&2; exit 1 ;;
esac

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -f "$SCRIPT_DIR/../manage/wireguard-p2p.py" ]; then
    MANAGER="$SCRIPT_DIR/../manage/wireguard-p2p.py"
else
    MANAGER="$SCRIPT_DIR/wireguard-p2p.py"
fi
TARGET=/opt/wireguard-p2p
SERVICE_USER=wireguard-p2p
CONFIG_DIR=/etc/wireguard-p2p
KEY_FILE="$CONFIG_DIR/notify.key"

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    NOLOGIN=$(command -v nologin || true)
    [ -n "$NOLOGIN" ] || NOLOGIN=/usr/sbin/nologin
    useradd --system --home-dir /nonexistent --shell "$NOLOGIN" "$SERVICE_USER"
fi
install -d -m 0750 "$CONFIG_DIR"
KEY_FILE="$KEY_FILE" OVERLAY_IP="$OVERLAY_IP" python3 - <<'PY'
import os, urllib.error, urllib.request
path = os.environ["KEY_FILE"]
overlay_ip = os.environ["OVERLAY_IP"]
request = urllib.request.Request("http://10.0.0.1:8899/bootstrap/server-key")
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
try:
    with opener.open(request, timeout=10) as response:
        data = response.read()
except urllib.error.HTTPError as exc:
    if exc.code == 403:
        raise SystemExit(
            "Server {} is not authorized. On the VPS run: sudo wireguard-p2p server add {}".format(
                overlay_ip, overlay_ip
            )
        )
    raise
if len(data.strip()) < 32:
    raise SystemExit("VPS returned an invalid notification key")
with open(path, "wb") as handle:
    handle.write(data)
PY
chown "$SERVICE_USER:$SERVICE_USER" "$KEY_FILE"
chmod 0400 "$KEY_FILE"

install -d -m 0755 "$TARGET"
for f in p2p_agent.py candidates.py portmap.py portmap_daemon.py; do
    install -m 0644 "$SCRIPT_DIR/$f" "$TARGET/$f"
done
sed -e "s/__SERVICE_USER__/$SERVICE_USER/g" -e "s/__OVERLAY_IP__/$OVERLAY_IP/g" "$SCRIPT_DIR/wireguard-p2p-agent.service" > /etc/systemd/system/wireguard-p2p-agent.service
sed -e "s/__SERVICE_USER__/$SERVICE_USER/g" -e "s/Environment=P2P_INTERFACE=wg0/Environment=P2P_INTERFACE=$WG_INTERFACE/" "$SCRIPT_DIR/wireguard-p2p-portmap.service" > /etc/systemd/system/wireguard-p2p-portmap.service
install -m 0755 "$MANAGER" /usr/local/bin/wireguard-p2p
systemctl daemon-reload
systemctl enable wireguard-p2p-agent.service wireguard-p2p-portmap.service
systemctl restart wireguard-p2p-portmap.service
systemctl restart wireguard-p2p-agent.service
printf 'Installed managed P2P server %s. Future updates: sudo wireguard-p2p update\n' "$OVERLAY_IP"
