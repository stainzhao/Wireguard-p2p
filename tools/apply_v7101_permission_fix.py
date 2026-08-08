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


# 1) Bump patch release consistently across runtime, clients, docs, and tests.
version_files = [
    "README.md",
    "p2p/wireguard-p2p-client/main.go",
    "p2p/wireguard-p2p-client/cross_platform_test.go",
    "p2p/wireguard-p2p/vps/peers_api.py",
    "p2p/wireguard-p2p/linux/p2p_agent.py",
    "p2p/wireguard-p2p/manage/wireguard-p2p.py",
    "p2p/wireguard-p2p/docs/architecture.md",
    "p2p/wireguard-p2p/docs/operations.md",
    "p2p/wireguard-p2p/tests/test_ipv4_punch.py",
    "p2p/wireguard-p2p/tests/test_ipv6_punch.py",
    "p2p/wireguard-p2p/tests/test_runtime.py",
]
for name in version_files:
    text = read(name)
    if "7.10.0" not in text:
        raise RuntimeError("expected 7.10.0 in " + name)
    write(name, text.replace("7.10.0", "7.10.1"))

# 2) Fresh installs: make the config directory traversable by the service account.
for name in (
    "p2p/wireguard-p2p/vps/install_vps.sh",
    "p2p/wireguard-p2p/linux/install_server.sh",
):
    text = read(name)
    text = replace_once(
        text,
        'install -d -m 0750 "$CONFIG_DIR"\n',
        'install -d -m 0750 "$CONFIG_DIR"\nchown root:"$SERVICE_USER" "$CONFIG_DIR"\nchmod 0750 "$CONFIG_DIR"\n',
        name + " config directory ownership",
    )
    write(name, text)

# 3) Managed upgrades/status run as root should self-heal v7.10.0 permission damage.
name = "p2p/wireguard-p2p/manage/wireguard-p2p.py"
text = read(name)
text = replace_once(
    text,
    'TOKEN_FILE = Path(os.environ.get("P2P_GITHUB_TOKEN_FILE", "/etc/wireguard-p2p/github.token"))\n',
    'CONFIG_DIR = Path(os.environ.get("P2P_CONFIG_DIR", "/etc/wireguard-p2p"))\nTOKEN_FILE = Path(os.environ.get("P2P_GITHUB_TOKEN_FILE", "/etc/wireguard-p2p/github.token"))\n',
    "manager config dir constant",
)
repair_func = '''\n\ndef repair_config_permissions(role):\n    """Repair service-account access after the v7.10.0 fresh-install regression."""\n    if not CONFIG_DIR.exists():\n        return\n    try:\n        shutil.chown(CONFIG_DIR, user="root", group="wireguard-p2p")\n    except LookupError as exc:\n        raise RuntimeError("wireguard-p2p service account is missing") from exc\n    os.chmod(CONFIG_DIR, 0o750)\n\n    key_file = CONFIG_DIR / "notify.key"\n    if key_file.exists():\n        shutil.chown(key_file, user="wireguard-p2p", group="wireguard-p2p")\n        os.chmod(key_file, 0o400)\n\n    if role == "vps":\n        for registry in (SERVER_REGISTRY_FILE, RELAY_ONLY_REGISTRY_FILE):\n            if registry.exists():\n                shutil.chown(registry, user="root", group="wireguard-p2p")\n                os.chmod(registry, 0o640)\n'''
text = replace_once(
    text,
    '\ndef detect_role():\n',
    repair_func + '\n\ndef detect_role():\n',
    "manager permission repair function",
)
text = replace_once(
    text,
    '    role = detect_role()\n    force = "--force" in sys.argv[2:]\n',
    '    role = detect_role()\n    if os.geteuid() == 0:\n        repair_config_permissions(role)\n    force = "--force" in sys.argv[2:]\n',
    "manager root self-heal call",
)
write(name, text)

# 4) Regression tests: installer ownership and functional repair behavior.
name = "p2p/wireguard-p2p/tests/test_runtime.py"
text = read(name)
text = replace_once(
    text,
    'candidates = load_module("candidates_runtime", LINUX / "candidates.py")\n',
    'candidates = load_module("candidates_runtime", LINUX / "candidates.py")\nmanager = load_module("manager_runtime", ROOT / "manage" / "wireguard-p2p.py")\n',
    "runtime manager import",
)
anchor = '''    def test_managed_installers_restart_existing_services(self):\n        client_installer = (ROOT.parent / "wireguard-p2p-client" / "deploy" / "linux" / "install.sh").read_text(encoding="utf-8")\n        server_installer = (LINUX / "install_server.sh").read_text(encoding="utf-8")\n        vps_installer = (ROOT / "vps" / "install_vps.sh").read_text(encoding="utf-8")\n        self.assertIn("systemctl restart wireguard-p2p-client.service", client_installer)\n        self.assertIn("systemctl restart wireguard-p2p-agent.service", server_installer)\n        self.assertIn("systemctl restart wireguard-p2p-portmap.service", server_installer)\n        self.assertIn("systemctl restart peers-api.service", vps_installer)\n\n'''
replacement = anchor + '''    def test_config_directory_is_traversable_by_service_account(self):\n        server_installer = (LINUX / "install_server.sh").read_text(encoding="utf-8")\n        vps_installer = (ROOT / "vps" / "install_vps.sh").read_text(encoding="utf-8")\n        for installer in (server_installer, vps_installer):\n            self.assertIn('chown root:"$SERVICE_USER" "$CONFIG_DIR"', installer)\n            self.assertIn('chmod 0750 "$CONFIG_DIR"', installer)\n\n    def test_manager_repairs_v7100_config_permissions(self):\n        old_config = manager.CONFIG_DIR\n        old_servers = manager.SERVER_REGISTRY_FILE\n        old_relay = manager.RELAY_ONLY_REGISTRY_FILE\n        with tempfile.TemporaryDirectory() as tmp:\n            config = pathlib.Path(tmp) / "wireguard-p2p"\n            config.mkdir(mode=0o700)\n            key = config / "notify.key"\n            servers = config / "servers.conf"\n            relay = config / "relay-only.conf"\n            key.write_text("x" * 64, encoding="ascii")\n            servers.write_text("10.0.0.2\\n", encoding="ascii")\n            relay.write_text("", encoding="ascii")\n            os.chmod(key, 0o600)\n            os.chmod(servers, 0o600)\n            os.chmod(relay, 0o600)\n            try:\n                manager.CONFIG_DIR = config\n                manager.SERVER_REGISTRY_FILE = servers\n                manager.RELAY_ONLY_REGISTRY_FILE = relay\n                with mock.patch.object(manager.shutil, "chown") as chown:\n                    manager.repair_config_permissions("vps")\n                self.assertEqual(config.stat().st_mode & 0o777, 0o750)\n                self.assertEqual(key.stat().st_mode & 0o777, 0o400)\n                self.assertEqual(servers.stat().st_mode & 0o777, 0o640)\n                self.assertEqual(relay.stat().st_mode & 0o777, 0o640)\n                chown.assert_any_call(config, user="root", group="wireguard-p2p")\n                chown.assert_any_call(key, user="wireguard-p2p", group="wireguard-p2p")\n                chown.assert_any_call(servers, user="root", group="wireguard-p2p")\n            finally:\n                manager.CONFIG_DIR = old_config\n                manager.SERVER_REGISTRY_FILE = old_servers\n                manager.RELAY_ONLY_REGISTRY_FILE = old_relay\n\n'''
text = replace_once(text, anchor, replacement, "runtime permission regression tests")
write(name, text)

print("Applied v7.10.1 permission fix")
