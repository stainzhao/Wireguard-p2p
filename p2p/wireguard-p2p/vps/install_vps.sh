#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || { echo "Run as root." >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required." >&2; exit 1; }
command -v systemctl >/dev/null 2>&1 || { echo "systemd is required." >&2; exit 1; }
command -v wg >/dev/null 2>&1 || { echo "wireguard-tools is required." >&2; exit 1; }
command -v useradd >/dev/null 2>&1 || { echo "useradd is required." >&2; exit 1; }

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -f "$SCRIPT_DIR/../manage/wireguard-p2p.py" ]; then
    MANAGER="$SCRIPT_DIR/../manage/wireguard-p2p.py"
else
    MANAGER="$SCRIPT_DIR/wireguard-p2p.py"
fi
SERVICE_USER=wireguard-p2p
CONFIG_DIR=/etc/wireguard-p2p
KEY_FILE="$CONFIG_DIR/notify.key"
TOKEN_FILE="$CONFIG_DIR/github.token"
SERVER_REGISTRY_FILE="$CONFIG_DIR/servers.conf"
RELAY_ONLY_REGISTRY_FILE="$CONFIG_DIR/relay-only.conf"

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    NOLOGIN=$(command -v nologin || true)
    [ -n "$NOLOGIN" ] || NOLOGIN=/usr/sbin/nologin
    useradd --system --home-dir /nonexistent --shell "$NOLOGIN" "$SERVICE_USER"
fi
install -d -m 0755 /opt/wireguard-p2p
install -d -o root -g "$SERVICE_USER" -m 0750 "$CONFIG_DIR"

if [ ! -s "$KEY_FILE" ]; then
    KEY_FILE="$KEY_FILE" python3 - <<'PY'
import os, secrets
path = os.environ["KEY_FILE"]
with open(path, "w", encoding="ascii") as handle:
    handle.write(secrets.token_hex(32) + "\n")
PY
fi
chown "$SERVICE_USER:$SERVICE_USER" "$KEY_FILE"
chmod 0400 "$KEY_FILE"

if [ ! -e "$SERVER_REGISTRY_FILE" ]; then
    : > "$SERVER_REGISTRY_FILE"
fi
if [ ! -e "$RELAY_ONLY_REGISTRY_FILE" ]; then
    : > "$RELAY_ONLY_REGISTRY_FILE"
fi
chown root:"$SERVICE_USER" "$SERVER_REGISTRY_FILE" "$RELAY_ONLY_REGISTRY_FILE"
chmod 0640 "$SERVER_REGISTRY_FILE" "$RELAY_ONLY_REGISTRY_FILE"

if [ -n "${P2P_GITHUB_TOKEN:-}" ]; then
    umask 077
    printf '%s\n' "$P2P_GITHUB_TOKEN" > "$TOKEN_FILE"
    chown root:root "$TOKEN_FILE"
    chmod 0600 "$TOKEN_FILE"
fi

install -m 0644 "$SCRIPT_DIR/peers_api.py" /opt/wireguard-p2p/peers_api.py
install -m 0644 "$SCRIPT_DIR/peers-api.service" /etc/systemd/system/peers-api.service
install -m 0755 "$MANAGER" /usr/local/bin/wireguard-p2p
systemctl daemon-reload
systemctl enable peers-api.service
systemctl restart peers-api.service

P2P_EXPECTED_VERSION=$(python3 - <<'PY'
import re
with open('/opt/wireguard-p2p/peers_api.py', 'r') as handle:
    text = handle.read()
match = re.search(r'^VERSION\s*=\s*["\']([^"\']+)', text, re.M)
if not match:
    raise SystemExit('cannot determine installed coordinator version')
print(match.group(1))
PY
)
P2P_EXPECTED_VERSION="$P2P_EXPECTED_VERSION" python3 - <<'PY'
import json, os, time, urllib.request
expected = os.environ['P2P_EXPECTED_VERSION']
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
last = None
for _ in range(12):
    try:
        with opener.open('http://10.0.0.1:8899/health', timeout=2) as response:
            payload = json.loads(response.read().decode('utf-8'))
        if payload.get('ok') and payload.get('version') == expected:
            break
        last = 'unexpected health payload: {!r}'.format(payload)
    except Exception as exc:
        last = str(exc)
    time.sleep(1)
else:
    raise SystemExit('peers-api health check failed: {}'.format(last))
PY
systemctl is-active --quiet peers-api.service
printf 'Installed WireGuard P2P VPS %s. Future updates: sudo wireguard-p2p update\n' "$P2P_EXPECTED_VERSION"
