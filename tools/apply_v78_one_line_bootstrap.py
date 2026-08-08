#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION_OLD = "7.7.1"
VERSION_NEW = "7.8.0"


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


def write(path, text):
    target = ROOT / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def replace_once(text, old, new, label):
    if old not in text:
        raise RuntimeError(f"missing replacement anchor: {label}")
    return text.replace(old, new, 1)


# Version bump across current implementation and regression expectations.
for path in [
    "README.md",
    "p2p/wireguard-p2p-client/main.go",
    "p2p/wireguard-p2p-client/cross_platform_test.go",
    "p2p/wireguard-p2p/linux/p2p_agent.py",
    "p2p/wireguard-p2p/manage/wireguard-p2p.py",
    "p2p/wireguard-p2p/vps/peers_api.py",
    "p2p/wireguard-p2p/docs/operations.md",
    "p2p/wireguard-p2p/tests/test_ipv4_punch.py",
    "p2p/wireguard-p2p/tests/test_ipv6_punch.py",
    "p2p/wireguard-p2p/tests/test_runtime.py",
]:
    text = read(path)
    if VERSION_OLD not in text:
        raise RuntimeError(f"{path}: expected {VERSION_OLD}")
    write(path, text.replace(VERSION_OLD, VERSION_NEW))

# Managed VPS installer: no manual user creation/key generation/token file step.
write("p2p/wireguard-p2p/vps/install_vps.sh", r'''#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || { echo "Run as root." >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required." >&2; exit 1; }
command -v systemctl >/dev/null 2>&1 || { echo "systemd is required." >&2; exit 1; }
command -v wg >/dev/null 2>&1 || { echo "wireguard-tools is required." >&2; exit 1; }

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

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin "$SERVICE_USER"
fi
install -d -m 0755 /opt/wireguard-p2p
install -d -m 0750 "$CONFIG_DIR"

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
printf 'Installed WireGuard P2P VPS. Future updates: sudo wireguard-p2p update\n'
''')

# Linux P2P server installer: autodetect role IP and use one dedicated service user.
write("p2p/wireguard-p2p/linux/install_server.sh", r'''#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || { echo "Run as root." >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required." >&2; exit 1; }
command -v systemctl >/dev/null 2>&1 || { echo "systemd is required." >&2; exit 1; }
command -v wg >/dev/null 2>&1 || { echo "wireguard-tools is required." >&2; exit 1; }
command -v ip >/dev/null 2>&1 || { echo "iproute2 is required." >&2; exit 1; }

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
    10.0.0.2|10.0.0.5) ;;
    *) echo "This installer is only for P2P server roles 10.0.0.2/10.0.0.5; detected '${OVERLAY_IP:-none}'." >&2; exit 1 ;;
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
    useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin "$SERVICE_USER"
fi
install -d -m 0750 "$CONFIG_DIR"
if [ ! -s "$KEY_FILE" ]; then
    KEY_FILE="$KEY_FILE" python3 - <<'PY'
import os, urllib.request
path = os.environ["KEY_FILE"]
request = urllib.request.Request("http://10.0.0.1:8899/bootstrap/server-key")
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open(request, timeout=10) as response:
    data = response.read()
if len(data.strip()) < 32:
    raise SystemExit("VPS returned an invalid notification key")
with open(path, "wb") as handle:
    handle.write(data)
PY
fi
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
''')

# Bootstrap scripts served from the VPS update cache.
write("p2p/wireguard-p2p/bootstrap/bootstrap-linux-client.sh", r'''#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ] || { echo "Run through sudo: curl ... | sudo sh" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "curl is required." >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is required." >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { echo "tar is required." >&2; exit 1; }
BASE=${P2P_UPDATE_BASE:-http://10.0.0.1:8899/updates}
WG_INTERFACE=${P2P_INTERFACE:-${1:-wg0}}
case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) echo "Unsupported Linux architecture: $(uname -m)" >&2; exit 1 ;;
esac
FILE="wireguard-p2p-linux-$ARCH.tar.gz"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM
curl -fsSL "$BASE/$FILE" -o "$TMP/$FILE"
curl -fsSL "$BASE/SHA256SUMS" -o "$TMP/SHA256SUMS"
awk -v f="$FILE" '$2 == f {print; found=1} END {if (!found) exit 1}' "$TMP/SHA256SUMS" > "$TMP/check"
(cd "$TMP" && sha256sum -c check)
mkdir "$TMP/pkg"
tar -xzf "$TMP/$FILE" -C "$TMP/pkg"
exec "$TMP/pkg/install.sh" --interface "$WG_INTERFACE"
''')

write("p2p/wireguard-p2p/bootstrap/bootstrap-linux-server.sh", r'''#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ] || { echo "Run through sudo: curl ... | sudo sh" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "curl is required." >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is required." >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { echo "tar is required." >&2; exit 1; }
BASE=${P2P_UPDATE_BASE:-http://10.0.0.1:8899/updates}
WG_INTERFACE=${P2P_INTERFACE:-${1:-wg0}}
FILE=wireguard-p2p-server.tar.gz
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM
curl -fsSL "$BASE/$FILE" -o "$TMP/$FILE"
curl -fsSL "$BASE/SHA256SUMS" -o "$TMP/SHA256SUMS"
awk -v f="$FILE" '$2 == f {print; found=1} END {if (!found) exit 1}' "$TMP/SHA256SUMS" > "$TMP/check"
(cd "$TMP" && sha256sum -c check)
mkdir "$TMP/pkg"
tar -xzf "$TMP/$FILE" -C "$TMP/pkg"
exec "$TMP/pkg/install_server.sh" --interface "$WG_INTERFACE"
''')

write("p2p/wireguard-p2p/bootstrap/bootstrap-vps.py", r'''#!/usr/bin/env python3
"""Secure one-command bootstrap for a private GitHub VPS release."""
import hashlib
import json
import os
import pathlib
import subprocess
import tarfile
import tempfile
import urllib.request

REPO = os.environ.get("P2P_GITHUB_REPO", "stainzhao/p2p")
TOKEN = os.environ.get("P2P_GITHUB_TOKEN", "").strip()
if not TOKEN:
    raise SystemExit("P2P_GITHUB_TOKEN is required")
HEADERS = {
    "Authorization": "Bearer " + TOKEN,
    "Accept": "application/vnd.github+json",
    "User-Agent": "wireguard-p2p-bootstrap",
}
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def get(url, accept=None):
    headers = dict(HEADERS)
    if accept:
        headers["Accept"] = accept
    with opener.open(urllib.request.Request(url, headers=headers), timeout=120) as response:
        return response.read()

release = json.loads(get(f"https://api.github.com/repos/{REPO}/releases/latest").decode())
assets = {item["name"]: item for item in release.get("assets", [])}
manifest_meta = assets.get("manifest.json")
if not manifest_meta:
    raise SystemExit("latest release has no manifest.json")
manifest = json.loads(get(manifest_meta["url"], "application/octet-stream").decode())
vps = manifest.get("assets", {}).get("vps-linux") or {}
name = vps.get("file", "")
meta = assets.get(name)
if not meta:
    raise SystemExit("latest release has no VPS package")
data = get(meta["url"], "application/octet-stream")
if hashlib.sha256(data).hexdigest() != vps.get("sha256") or len(data) != int(vps.get("size", 0)):
    raise SystemExit("VPS package verification failed")

with tempfile.TemporaryDirectory(prefix="wireguard-p2p-bootstrap-") as tmp:
    root = pathlib.Path(tmp).resolve()
    archive_path = root / "vps.tar.gz"
    archive_path.write_bytes(data)
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive.getmembers():
            destination = (root / member.name).resolve()
            if root != destination and root not in destination.parents:
                raise SystemExit("unsafe path in VPS archive")
        archive.extractall(root)
    installer = root / "install_vps.sh"
    if not installer.is_file():
        raise SystemExit("VPS package has no install_vps.sh")
    env = dict(os.environ)
    env["P2P_GITHUB_TOKEN"] = TOKEN
    subprocess.run(["sh", str(installer)], check=True, env=env)
    subprocess.run(["/usr/local/bin/wireguard-p2p", "update", "--force"], check=True, env=env)
print("WireGuard P2P VPS bootstrap complete.")
''')

# Coordinator: allow only the two fixed server overlay identities to retrieve the HMAC key.
path = "p2p/wireguard-p2p/vps/peers_api.py"
text = read(path)
anchor = '''def update_asset_path(request_path):\n'''
helper = '''def bootstrap_server_key(source_ip):\n    if source_ip not in SERVER_IPS:\n        raise PermissionError("server bootstrap key is restricted to server peers")\n    if not NOTIFY_KEY or len(NOTIFY_KEY) < 32:\n        raise RuntimeError("notification key unavailable")\n    return NOTIFY_KEY + b"\\n"\n\n\n'''
text = replace_once(text, anchor, helper + anchor, "bootstrap key helper")
get_anchor = '''    def do_GET(self):\n        try:\n            if self.path.startswith("/updates/"):\n'''
get_repl = '''    def do_GET(self):\n        try:\n            if self.path == "/bootstrap/server-key":\n                try:\n                    body = bootstrap_server_key(self.client_address[0])\n                except PermissionError as exc:\n                    self.send_json(403, {"error": str(exc)})\n                    return\n                self.send_response(200)\n                self.send_header("Content-Type", "application/octet-stream")\n                self.send_header("Cache-Control", "no-store")\n                self.send_header("Content-Length", str(len(body)))\n                self.end_headers()\n                self.wfile.write(body)\n                return\n            if self.path.startswith("/updates/"):\n'''
text = replace_once(text, get_anchor, get_repl, "server-key GET endpoint")
write(path, text)

# VPS updater also caches and validates SHA256SUMS for bootstrap scripts.
path = "p2p/wireguard-p2p/manage/wireguard-p2p.py"
text = read(path)
anchor = '''    downloads = {}\n    for key, meta in manifest_assets.items():\n        file_name = meta.get("file", "")\n        release_meta = release_assets.get(file_name)\n        if not release_meta:\n            raise RuntimeError("release is missing " + file_name)\n        data = release_asset_bytes(release_meta, headers)\n        verify_asset(data, meta)\n        downloads[file_name] = data\n\n'''
repl = anchor + '''    sums_meta = release_assets.get("SHA256SUMS")\n    if not sums_meta:\n        raise RuntimeError("release is missing SHA256SUMS")\n    sums_data = release_asset_bytes(sums_meta, headers)\n    sums_lines = set(sums_data.decode("utf-8").splitlines())\n    for meta in manifest_assets.values():\n        expected = "{}  {}".format(meta.get("sha256", ""), meta.get("file", ""))\n        if expected not in sums_lines:\n            raise RuntimeError("SHA256SUMS does not match manifest for " + meta.get("file", "asset"))\n    downloads["SHA256SUMS"] = sums_data\n\n'''
text = replace_once(text, anchor, repl, "cache SHA256SUMS")
write(path, text)

# CI packaging: include first-install entry points in immutable releases.
path = ".github/workflows/ci.yml"
text = read(path)
text = replace_once(
    text,
    '''          test -f p2p/wireguard-p2p/vps/install_vps.sh\n''',
    '''          test -f p2p/wireguard-p2p/vps/install_vps.sh\n          test -f p2p/wireguard-p2p/bootstrap/bootstrap-linux-client.sh\n          test -f p2p/wireguard-p2p/bootstrap/bootstrap-linux-server.sh\n          test -f p2p/wireguard-p2p/bootstrap/bootstrap-vps.py\n''',
    "CI hygiene bootstraps",
)
text = replace_once(
    text,
    '''          sh -n p2p/wireguard-p2p-client/deploy/linux/uninstall.sh\n''',
    '''          sh -n p2p/wireguard-p2p-client/deploy/linux/uninstall.sh\n          sh -n p2p/wireguard-p2p/bootstrap/bootstrap-linux-client.sh\n          sh -n p2p/wireguard-p2p/bootstrap/bootstrap-linux-server.sh\n          python -m py_compile p2p/wireguard-p2p/bootstrap/bootstrap-vps.py\n''',
    "CI validate bootstraps",
)
text = replace_once(
    text,
    '''             p2p/wireguard-p2p/linux/wireguard-p2p-portmap.service \\\n             dist/server/\n          cp p2p/wireguard-p2p/manage/wireguard-p2p.py dist/server/\n''',
    '''             p2p/wireguard-p2p/linux/wireguard-p2p-portmap.service \\\n             p2p/wireguard-p2p/linux/install_server.sh \\\n             dist/server/\n          cp p2p/wireguard-p2p/manage/wireguard-p2p.py dist/server/\n''',
    "server package installer",
)
text = replace_once(
    text,
    '''          cp p2p/wireguard-p2p/vps/peers_api.py \\\n             p2p/wireguard-p2p/vps/peers-api.service \\\n             dist/vps/\n''',
    '''          cp p2p/wireguard-p2p/vps/peers_api.py \\\n             p2p/wireguard-p2p/vps/peers-api.service \\\n             p2p/wireguard-p2p/vps/install_vps.sh \\\n             dist/vps/\n''',
    "VPS package installer",
)
text = replace_once(
    text,
    '''          tar -C dist/vps -czf dist/release/wireguard-p2p-vps.tar.gz .\n\n          python - <<'PY'\n''',
    '''          tar -C dist/vps -czf dist/release/wireguard-p2p-vps.tar.gz .\n          cp p2p/wireguard-p2p/bootstrap/bootstrap-linux-client.sh dist/release/\n          cp p2p/wireguard-p2p/bootstrap/bootstrap-linux-server.sh dist/release/\n          cp p2p/wireguard-p2p/bootstrap/bootstrap-vps.py dist/release/\n\n          python - <<'PY'\n''',
    "release bootstrap assets",
)
text = replace_once(
    text,
    '''              'vps-linux': 'wireguard-p2p-vps.tar.gz',\n          }\n''',
    '''              'vps-linux': 'wireguard-p2p-vps.tar.gz',\n              'bootstrap-linux-client': 'bootstrap-linux-client.sh',\n              'bootstrap-linux-server': 'bootstrap-linux-server.sh',\n              'bootstrap-vps': 'bootstrap-vps.py',\n          }\n''',
    "manifest bootstrap assets",
)
text = replace_once(
    text,
    '''          sha256sum dist/release/* > dist/release/SHA256SUMS\n''',
    '''          (cd dist/release && find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%f\\n' | sort | xargs sha256sum > SHA256SUMS)\n''',
    "basename SHA256SUMS",
)
write(path, text)

# Regression coverage for bootstrap trust boundary and packaging semantics.
path = "p2p/wireguard-p2p/tests/test_runtime.py"
text = read(path)
insert = '''\n    def test_server_bootstrap_key_is_overlay_restricted(self):\n        original = api.NOTIFY_KEY\n        try:\n            api.NOTIFY_KEY = b"x" * 32\n            self.assertEqual(api.bootstrap_server_key("10.0.0.2"), b"x" * 32 + b"\\n")\n            self.assertEqual(api.bootstrap_server_key("10.0.0.5"), b"x" * 32 + b"\\n")\n            with self.assertRaises(PermissionError):\n                api.bootstrap_server_key("10.0.0.3")\n        finally:\n            api.NOTIFY_KEY = original\n\n    def test_one_line_bootstrap_assets_exist(self):\n        root = ROOT / "bootstrap"\n        for name in ("bootstrap-linux-client.sh", "bootstrap-linux-server.sh", "bootstrap-vps.py"):\n            self.assertTrue((root / name).is_file())\n        server_installer = (LINUX / "install_server.sh").read_text(encoding="utf-8")\n        self.assertIn("10.0.0.2|10.0.0.5", server_installer)\n        self.assertIn("/bootstrap/server-key", server_installer)\n\n'''
text = replace_once(text, '\n\nif __name__ == "__main__":\n', insert + '\nif __name__ == "__main__":\n', "runtime bootstrap tests")
write(path, text)

# User-facing one-line commands.
path = "README.md"
text = read(path)
append = r'''

## 真正的一行首次部署（v7.8+）

VPS（私有仓库，因此命令会安全提示输入一次 GitHub 只读 Token；Token 不出现在 shell history）：

```bash
read -rsp 'GitHub read token: ' T; echo; curl -fsSL -H "Authorization: Bearer $T" -H 'Accept: application/vnd.github.raw+json' 'https://api.github.com/repos/stainzhao/p2p/contents/p2p/wireguard-p2p/bootstrap/bootstrap-vps.py?ref=main' | sudo env P2P_GITHUB_TOKEN="$T" python3 -
```

`.2/.5` Linux P2P Server（只要求现有 WireGuard `wg0` 已经能到 `10.0.0.1`）：

```bash
curl -fsSL http://10.0.0.1:8899/updates/bootstrap-linux-server.sh | sudo sh
```

普通 Linux Client：

```bash
curl -fsSL http://10.0.0.1:8899/updates/bootstrap-linux-client.sh | sudo sh
```

Server 安装器会从 `wg0` 自动识别 `.2/.5`，统一使用专用 `wireguard-p2p` system user；若本机尚无 `notify.key`，只允许 `.2/.5` 通过 WireGuard overlay 从 VPS 获取。Client 自动识别 amd64/arm64。首次部署完成后，所有 Linux 角色继续统一使用 `sudo wireguard-p2p update`。
'''
if "## 真正的一行首次部署" not in text:
    text += append
write(path, text)

path = "p2p/wireguard-p2p/docs/operations.md"
text = read(path)
if "## 6. 一行首次部署" not in text:
    text += r'''

## 6. 一行首次部署

VPS 首次部署使用 README 中的私有 GitHub bootstrap 命令；它通过安全输入的只读 Token 下载并校验最新 VPS Release，安装后立即执行一次 `wireguard-p2p update --force`，从而把所有客户端/Server 包和 bootstrap 脚本缓存到 VPS。

随后 `.2/.5`：

```bash
curl -fsSL http://10.0.0.1:8899/updates/bootstrap-linux-server.sh | sudo sh
```

普通 Linux Client：

```bash
curl -fsSL http://10.0.0.1:8899/updates/bootstrap-linux-client.sh | sudo sh
```

首次安装与后续更新都不修改 WireGuard 密钥、VPS peer 或 `/24` relay baseline。Server 的 HMAC `notify.key` 只允许固定 overlay 身份 `10.0.0.2/10.0.0.5` 通过 WireGuard 内网领取。
'''
write(path, text)
