#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


def write(path, text):
    (ROOT / path).write_text(text, encoding="utf-8")


def replace_once(text, old, new, label):
    if old not in text:
        raise RuntimeError("missing anchor: " + label)
    return text.replace(old, new, 1)


# Fresh install directory ownership: root owns the directory, service group can traverse it.
for name in (
    "p2p/wireguard-p2p/vps/install_vps.sh",
    "p2p/wireguard-p2p/linux/install_server.sh",
):
    text = read(name)
    text = replace_once(
        text,
        'install -d -m 0750 "$CONFIG_DIR"\nchown root:"$SERVICE_USER" "$CONFIG_DIR"\nchmod 0750 "$CONFIG_DIR"\n',
        'install -d -o root -g "$SERVICE_USER" -m 0750 "$CONFIG_DIR"\n',
        name + " atomic config ownership",
    )
    write(name, text)

# Bootstrap must not depend on the archive preserving executable mode.
name = "p2p/wireguard-p2p/bootstrap/bootstrap-linux-server.sh"
text = read(name)
text = replace_once(
    text,
    '"$TMP/pkg/install_server.sh" --interface "$WG_INTERFACE"\n',
    'sh "$TMP/pkg/install_server.sh" --interface "$WG_INTERFACE"\n',
    "server bootstrap shell invocation",
)
write(name, text)

# Python 3.6 compatibility for the manager.
name = "p2p/wireguard-p2p/manage/wireguard-p2p.py"
text = read(name)
text = replace_once(
    text,
    'def safe_extract(data, target):\n',
    'def unlink_if_exists(path):\n    try:\n        Path(path).unlink()\n    except FileNotFoundError:\n        pass\n\n\ndef safe_extract(data, target):\n',
    "unlink helper",
)
text = text.replace('archive_path.unlink(missing_ok=True)', 'unlink_if_exists(archive_path)')
text = text.replace('next_link.unlink(missing_ok=True)', 'unlink_if_exists(next_link)')
text = text.replace('rollback_link.unlink(missing_ok=True)', 'unlink_if_exists(rollback_link)')
text = replace_once(
    text,
    'subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)',
    'subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, check=False)',
    "Python 3.6 subprocess output",
)
if "missing_ok=True" in text or "text=True" in text:
    raise RuntimeError("Python >=3.7/3.8-only manager API remains")
write(name, text)

# Installers must verify that the services survived restart and answer health checks.
name = "p2p/wireguard-p2p/vps/install_vps.sh"
text = read(name)
old = '''systemctl daemon-reload
systemctl enable peers-api.service
systemctl restart peers-api.service
printf 'Installed WireGuard P2P VPS. Future updates: sudo wireguard-p2p update\\n'
'''
new = '''systemctl daemon-reload
systemctl enable peers-api.service
systemctl restart peers-api.service

P2P_EXPECTED_VERSION=$(python3 - <<'PY'
import re
with open('/opt/wireguard-p2p/peers_api.py', 'r') as handle:
    text = handle.read()
match = re.search(r'^VERSION\\s*=\\s*["\\\']([^"\\\']+)', text, re.M)
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
printf 'Installed WireGuard P2P VPS %s. Future updates: sudo wireguard-p2p update\\n' "$P2P_EXPECTED_VERSION"
'''
text = replace_once(text, old, new, "VPS post-install health check")
write(name, text)

name = "p2p/wireguard-p2p/linux/install_server.sh"
text = read(name)
old = '''systemctl daemon-reload
systemctl enable wireguard-p2p-agent.service wireguard-p2p-portmap.service
systemctl restart wireguard-p2p-portmap.service
systemctl restart wireguard-p2p-agent.service
printf 'Installed managed P2P server %s. Future updates: sudo wireguard-p2p update\\n' "$OVERLAY_IP"
'''
new = '''systemctl daemon-reload
systemctl enable wireguard-p2p-agent.service wireguard-p2p-portmap.service
systemctl restart wireguard-p2p-portmap.service
systemctl restart wireguard-p2p-agent.service

P2P_EXPECTED_VERSION=$(python3 - <<'PY'
import re
with open('/opt/wireguard-p2p/p2p_agent.py', 'r') as handle:
    text = handle.read()
match = re.search(r'^VERSION\\s*=\\s*["\\\']([^"\\\']+)', text, re.M)
if not match:
    raise SystemExit('cannot determine installed Agent version')
print(match.group(1))
PY
)
OVERLAY_IP="$OVERLAY_IP" P2P_EXPECTED_VERSION="$P2P_EXPECTED_VERSION" python3 - <<'PY'
import json, os, time, urllib.request
address = os.environ['OVERLAY_IP']
expected = os.environ['P2P_EXPECTED_VERSION']
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
last = None
url = 'http://{}:8898/health'.format(address)
for _ in range(12):
    try:
        with opener.open(url, timeout=2) as response:
            payload = json.loads(response.read().decode('utf-8'))
        if payload.get('ok') and payload.get('version') == expected:
            break
        last = 'unexpected health payload: {!r}'.format(payload)
    except Exception as exc:
        last = str(exc)
    time.sleep(1)
else:
    raise SystemExit('P2P Agent health check failed: {}'.format(last))
PY
systemctl is-active --quiet wireguard-p2p-agent.service
systemctl is-active --quiet wireguard-p2p-portmap.service
printf 'Installed managed P2P server %s (%s). Future updates: sudo wireguard-p2p update\\n' "$OVERLAY_IP" "$P2P_EXPECTED_VERSION"
'''
text = replace_once(text, old, new, "server post-install health check")
write(name, text)

# README: explicitly document Python 3.6+ compatibility and installer health guarantees.
name = "README.md"
text = read(name)
text = replace_once(
    text,
    '前提：VPS 已有 `wg0=10.0.0.1`，并安装 `python3`、`wireguard-tools`、`systemd`。',
    '前提：VPS 已有 `wg0=10.0.0.1`，并安装 **Python 3.6+**、`wireguard-tools`、`systemd`。v7.10.1 起 Manager 避免使用仅 Python 3.7/3.8+ 提供的 API。',
    "README Python baseline",
)
text = replace_once(
    text,
    '启动并重启服务\n```',
    '启动并重启服务\n安装结束前验证 Agent `8898/health`，并确认 Agent 与 portmap 两个 systemd 服务仍为 active；验证失败则安装命令返回失败，不再误报成功。\n```',
    "README server health guarantee",
)
# Add VPS health guarantee after its verification block intro if not already present.
needle = '''验证：

```bash
curl -fsS http://10.0.0.1:8899/health
sudo wireguard-p2p version
sudo wireguard-p2p role list
```
'''
replacement = needle + '\n安装器会在输出成功前轮询 `8899/health` 并确认 `peers-api.service` 仍为 active。\n'
text = replace_once(text, needle, replacement, "README VPS health guarantee")
write(name, text)

# Regression tests for all four installation failures.
name = "p2p/wireguard-p2p/tests/test_runtime.py"
text = read(name)
anchor = '''    def test_config_directory_is_traversable_by_service_account(self):
        server_installer = (LINUX / "install_server.sh").read_text(encoding="utf-8")
        vps_installer = (ROOT / "vps" / "install_vps.sh").read_text(encoding="utf-8")
        for installer in (server_installer, vps_installer):
            self.assertIn('chown root:"$SERVICE_USER" "$CONFIG_DIR"', installer)
            self.assertIn('chmod 0750 "$CONFIG_DIR"', installer)

'''
replacement = '''    def test_config_directory_is_traversable_by_service_account(self):
        server_installer = (LINUX / "install_server.sh").read_text(encoding="utf-8")
        vps_installer = (ROOT / "vps" / "install_vps.sh").read_text(encoding="utf-8")
        for installer in (server_installer, vps_installer):
            self.assertIn('install -d -o root -g "$SERVICE_USER" -m 0750 "$CONFIG_DIR"', installer)

    def test_server_bootstrap_does_not_require_executable_archive_mode(self):
        bootstrap = (ROOT / "bootstrap" / "bootstrap-linux-server.sh").read_text(encoding="utf-8")
        self.assertIn('sh "$TMP/pkg/install_server.sh" --interface "$WG_INTERFACE"', bootstrap)

    def test_python36_manager_compatibility(self):
        source = (ROOT / "manage" / "wireguard-p2p.py").read_text(encoding="utf-8")
        self.assertNotIn("missing_ok=True", source)
        self.assertNotIn("text=True", source)
        self.assertIn("universal_newlines=True", source)

    def test_installers_verify_service_health_before_success(self):
        server_installer = (LINUX / "install_server.sh").read_text(encoding="utf-8")
        vps_installer = (ROOT / "vps" / "install_vps.sh").read_text(encoding="utf-8")
        self.assertIn("8898/health", server_installer)
        self.assertIn("systemctl is-active --quiet wireguard-p2p-agent.service", server_installer)
        self.assertIn("systemctl is-active --quiet wireguard-p2p-portmap.service", server_installer)
        self.assertIn("10.0.0.1:8899/health", vps_installer)
        self.assertIn("systemctl is-active --quiet peers-api.service", vps_installer)

'''
text = replace_once(text, anchor, replacement, "runtime installation regressions")
write(name, text)

print("Applied remaining v7.10.1 install fixes")
