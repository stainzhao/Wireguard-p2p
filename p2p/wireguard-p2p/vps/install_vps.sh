#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || { echo "Run as root." >&2; exit 1; }
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MANAGER_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../manage" && pwd)
install -d -m 0755 /opt/wireguard-p2p
install -m 0644 "$SCRIPT_DIR/peers_api.py" /opt/wireguard-p2p/peers_api.py
install -m 0644 "$SCRIPT_DIR/peers-api.service" /etc/systemd/system/peers-api.service
install -m 0755 "$MANAGER_DIR/wireguard-p2p.py" /usr/local/bin/wireguard-p2p
install -d -m 0700 /etc/wireguard-p2p
systemctl daemon-reload
systemctl enable peers-api.service
systemctl restart peers-api.service
cat <<'EOF'
Installed managed VPS updater.
For this private GitHub repository, configure a read-only token once:
  sudo sh -c 'umask 077; cat > /etc/wireguard-p2p/github.token'
Then paste the token, press Enter, Ctrl+D.
Future updates:
  sudo wireguard-p2p update
EOF
